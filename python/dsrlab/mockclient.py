"""Minimal, dependency-free HTTP and WebSocket clients for local dsmock only.

Every connection target is hard-coded to ``127.0.0.1``; redirects to any other
host are rejected.  The WebSocket implementation uses raw sockets so no third
party library is needed.
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import struct
import urllib.error
import urllib.request
from typing import Any

from .integration import validate_local_url

DEFAULT_TIMEOUT = 10


class HeadersDict(dict):
    """A dict whose string keys can be looked up case-insensitively."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._ci = {str(key).lower(): key for key in self.keys()}

    def _real_key(self, key: Any) -> Any:
        if isinstance(key, str):
            found = self._ci.get(key.lower())
            if found is not None:
                return found
        return key

    def __getitem__(self, key: Any) -> Any:
        return dict.__getitem__(self, self._real_key(key))

    def __contains__(self, key: Any) -> bool:
        return dict.__contains__(self, self._real_key(key))

    def get(self, key: Any, default: Any = None) -> Any:
        real = self._real_key(key)
        if dict.__contains__(self, real):
            return dict.__getitem__(self, real)
        return default


class _LocalOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when the target is still loopback."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        validate_local_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_LocalOnlyRedirectHandler())


def http_request(
    port: int,
    path: str,
    method: str = "GET",
    body: Any = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, HeadersDict, str]:
    """Perform an HTTP request against ``127.0.0.1:<port>`` only."""
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    normalized = path if str(path).startswith("/") else "/" + str(path)
    url = f"http://127.0.0.1:{port}{normalized}"
    validate_local_url(url)

    request_headers = dict(headers or {})
    data: bytes | None = None
    if body is not None:
        if isinstance(body, bytes):
            data = body
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")

    request = urllib.request.Request(url, data=data, method=method.upper(), headers=request_headers)
    opener = _opener()
    try:
        response = opener.open(request, timeout=DEFAULT_TIMEOUT)
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read()
            status = int(exc.code)
            headers = HeadersDict(exc.headers.items()) if exc.headers else HeadersDict()
        finally:
            exc.close()
        return status, headers, payload.decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"local mock request failed: {exc.reason}") from exc
    with response:
        payload = response.read()
        status = int(getattr(response, "status", None) or response.getcode())
        return status, HeadersDict(response.headers.items()), payload.decode("utf-8", errors="replace")


class WebSocketClient:
    """A tiny RFC 6455 client implementing only what the local mock needs."""

    def __init__(self, port: int) -> None:
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        self.port = port
        self.socket: socket.socket | None = None
        self._buffer = b""
        self.key = ""
        self.ops: list[int] = []
        self.events: list[str] = []
        self.heartbeat_acks = 0

    @property
    def connected(self) -> bool:
        return self.socket is not None

    def connect(self) -> "WebSocketClient":
        """Open a raw WebSocket connection to the local mock gateway."""
        if self.socket is not None:
            return self
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=DEFAULT_TIMEOUT)
        self.key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET /gateway HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {self.key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        try:
            connection.settimeout(DEFAULT_TIMEOUT)
            connection.sendall(request.encode("ascii"))
            header_bytes = b""
            while b"\r\n\r\n" not in header_bytes:
                chunk = connection.recv(4096)
                if not chunk:
                    raise RuntimeError("dsmock closed the socket during WebSocket handshake")
                header_bytes += chunk
            head, self._buffer = header_bytes.split(b"\r\n\r\n", 1)
            lines = head.decode("iso-8859-1").split("\r\n")
            match = re.match(r"HTTP/1\.[01]\s+(\d+)", lines[0])
            if not match or int(match.group(1)) != 101:
                raise RuntimeError(f"WebSocket upgrade failed: {lines[0]}")
            response_headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    response_headers[name.strip().lower()] = value.strip()
            if not response_headers.get("sec-websocket-accept"):
                raise RuntimeError("WebSocket upgrade response has no Sec-WebSocket-Accept header")
        except Exception:
            connection.close()
            raise
        connection.settimeout(5)
        self.socket = connection
        return self

    def _read_exact(self, count: int) -> bytes:
        if self.socket is None:
            raise RuntimeError("WebSocket client is not connected")
        while len(self._buffer) < count:
            chunk = self.socket.recv(max(4096, count - len(self._buffer)))
            if not chunk:
                raise ConnectionError("WebSocket connection closed by peer")
            self._buffer += chunk
        data, self._buffer = self._buffer[:count], self._buffer[count:]
        return data

    def recv_frame(self) -> tuple[int, bytes]:
        """Read one data frame; ping/pong frames are ignored."""
        first, second = self._read_exact(2)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read_exact(8))[0]
        mask = self._read_exact(4) if masked else None
        payload = self._read_exact(length) if length else b""
        if mask is not None and payload:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        if opcode == 0x8:
            raise ConnectionError("WebSocket close frame received")
        if opcode in (0x9, 0xA):
            return self.recv_frame()
        return opcode, payload

    def _record(self, message: dict[str, Any]) -> None:
        op = message.get("op")
        if isinstance(op, int) and not isinstance(op, bool):
            self.ops.append(op)
        if op == 0 and isinstance(message.get("t"), str):
            self.events.append(message["t"])
        elif op == 11:
            self.heartbeat_acks += 1

    def recv_json(self, timeout: float = 5) -> dict[str, Any]:
        """Receive the next JSON text frame and record its op/event."""
        if self.socket is None:
            raise RuntimeError("WebSocket client is not connected")
        self.socket.settimeout(timeout)
        try:
            while True:
                opcode, payload = self.recv_frame()
                if opcode not in (0x1, 0x2):
                    continue
                message = json.loads(payload.decode("utf-8", errors="replace"))
                if not isinstance(message, dict):
                    continue
                self._record(message)
                return message
        finally:
            if self.socket is not None:
                self.socket.settimeout(5)

    def send_frame(self, opcode: int, payload: bytes) -> None:
        """Send a masked client frame (clients must mask frames)."""
        if self.socket is None:
            raise RuntimeError("WebSocket client is not connected")
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes((0x80 | opcode, 0x80 | length))
        elif length <= 0xFFFF:
            header = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack(">H", length)
        else:
            header = bytes((0x80 | opcode, 0x80 | 127)) + struct.pack(">Q", length)
        masked_payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(header + mask + masked_payload)

    def send_json(self, obj: dict[str, Any]) -> None:
        self.send_frame(0x1, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def send_identify(self, token: str = "DUMMY") -> None:
        """Send a synthetic IDENTIFY frame; never use a real token here."""
        self.send_json(
            {
                "op": 2,
                "d": {
                    "token": token,
                    "intents": 513,
                    "properties": {"os": "linux", "browser": "dsrlab", "device": "dsrlab"},
                },
            }
        )

    def send_heartbeat(self) -> None:
        self.send_json({"op": 1, "d": None})

    def close(self) -> None:
        """Close the WebSocket cleanly, best effort."""
        if self.socket is None:
            return
        connection = self.socket
        try:
            self.send_frame(0x8, b"")
        except (OSError, RuntimeError):
            pass
        self.socket = None
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()


def collect_gateway_trace(port: int) -> dict[str, Any]:
    """Drive one local gateway session and return a deterministic trace."""
    client = WebSocketClient(port)
    try:
        client.connect()
        hello = client.recv_json(timeout=5)
        if hello.get("op") != 10:
            raise RuntimeError(f"expected HELLO (op 10), got op {hello.get('op')}")

        client.send_identify()
        wanted = {"READY", "MESSAGE_CREATE"}
        seen: set[str] = set()
        for _ in range(20):
            message = client.recv_json(timeout=5)
            event = message.get("t")
            if isinstance(event, str):
                seen.add(event)
            if wanted.issubset(seen):
                break
        else:
            raise RuntimeError(f"gateway did not dispatch all events; got {sorted(seen)}")

        client.send_heartbeat()
        for _ in range(10):
            if client.heartbeat_acks >= 1:
                break
            client.recv_json(timeout=5)
        if client.heartbeat_acks < 1:
            raise RuntimeError("gateway did not acknowledge HEARTBEAT")
    finally:
        client.close()

    return {
        "connected": True,
        "ops": list(client.ops),
        "events": list(client.events),
        "heartbeat_acks": client.heartbeat_acks,
        "disconnected": True,
    }
