package mock_test

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"dsrlab/internal/mock"
)

func newTestServer(t *testing.T) *mock.Server {
	t.Helper()
	server, err := mock.New(mock.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Run() }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop after Close")
		}
	})
	return server
}

func request(t *testing.T, client *http.Client, method, url string, body io.Reader,
	headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func decodeObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("invalid JSON %q: %v", data, err)
	}
	return object
}

func assertJSON(t *testing.T, data []byte, want map[string]any) {
	t.Helper()
	got := decodeObject(t, data)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON mismatch: got %v, want %v", got, want)
	}
}

func TestHealthAndGatewayDiscovery(t *testing.T) {
	server := newTestServer(t)
	base := "http://" + server.Addr()
	client := &http.Client{Timeout: 3 * time.Second}

	resp, body := request(t, client, http.MethodGet, base+"/health", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", resp.StatusCode)
	}
	assertJSON(t, body, map[string]any{"ok": true})

	resp, body = request(t, client, http.MethodGet, base+"/api/v10/gateway", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gateway status %d", resp.StatusCode)
	}
	assertJSON(t, body, map[string]any{
		"url":    fmt.Sprintf("ws://127.0.0.1:%d/gateway", server.Port()),
		"shards": float64(1),
	})
}

func TestSyntheticRestEndpoints(t *testing.T) {
	server := newTestServer(t)
	base := "http://" + server.Addr()
	client := &http.Client{Timeout: 3 * time.Second}

	resp, body := request(t, client, http.MethodGet, base+"/api/v10/users/@me", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("user status %d", resp.StatusCode)
	}
	assertJSON(t, body, map[string]any{"id": "100000000000000001", "username": "DUMMY_USER", "bot": true})

	resp, body = request(t, client, http.MethodGet,
		base+"/api/v10/guilds/100000000000000002", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("guild status %d", resp.StatusCode)
	}
	assertJSON(t, body, map[string]any{"id": "100000000000000002", "name": "DUMMY_GUILD"})

	resp, body = request(t, client, http.MethodPost,
		base+"/api/v10/channels/100000000000000003/messages", strings.NewReader(`{"content":"hi"}`), nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("message status %d", resp.StatusCode)
	}
	assertJSON(t, body, map[string]any{"id": "100000000000000005", "content": "DUMMY_MESSAGE"})
}

func TestRateLimitHeaders(t *testing.T) {
	server := newTestServer(t)
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, body := request(t, client, http.MethodGet,
		"http://"+server.Addr()+"/api/v10/rate-limited", nil, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d", resp.StatusCode)
	}
	wantHeaders := map[string]string{
		"Retry-After": "1", "X-RateLimit-Limit": "5", "X-RateLimit-Remaining": "0",
	}
	for name, want := range wantHeaders {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("header %s: got %q, want %q", name, got, want)
		}
	}
	reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
	if err != nil || reset < time.Now().Unix() || reset > time.Now().Unix()+5 {
		t.Fatalf("bad X-RateLimit-Reset %q (err=%v)", resp.Header.Get("X-RateLimit-Reset"), err)
	}
	assertJSON(t, body, map[string]any{"message": "DUMMY_RATE_LIMIT", "retry_after": float64(1)})
}

func TestOAuthWebhookAndForbidden(t *testing.T) {
	server := newTestServer(t)
	base := "http://" + server.Addr()
	client := &http.Client{Timeout: 3 * time.Second}

	resp, body := request(t, client, http.MethodPost, base+"/api/v10/oauth2/token",
		strings.NewReader("grant_type=client_credentials"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("oauth status %d", resp.StatusCode)
	}
	assertJSON(t, body, map[string]any{
		"access_token": "DUMMY_ACCESS_TOKEN", "token_type": "Bearer",
		"expires_in": float64(3600), "scope": "identify",
	})

	resp, body = request(t, client, http.MethodPost,
		base+"/api/v10/webhooks/100000000000000004/DUMMYWEBHOOK", strings.NewReader("{}"), nil)
	if resp.StatusCode != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("webhook: status=%d body=%q", resp.StatusCode, body)
	}

	resp, body = request(t, client, http.MethodGet, base+"/api/v10/forbidden", nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forbidden status %d", resp.StatusCode)
	}
	assertJSON(t, body, map[string]any{"message": "DUMMY_FORBIDDEN", "code": float64(50013)})
}

func TestUnknownRouteIsJSON(t *testing.T) {
	server := newTestServer(t)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, body := request(t, client, http.MethodGet,
		"http://"+server.Addr()+"/api/v10/does-not-exist", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if object := decodeObject(t, body); object["message"] == "" {
		t.Fatalf("missing JSON message: %q", body)
	}
}

func TestAuthorizationIsRedactedInLogs(t *testing.T) {
	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)

	server := newTestServer(t)
	client := &http.Client{Timeout: 3 * time.Second}
	secretValue := "Bearer DUMMY_SUPER_SECRET_AUTH_VALUE"
	_, body := request(t, client, http.MethodGet, "http://"+server.Addr()+"/health", nil,
		map[string]string{"Authorization": secretValue})
	if strings.Contains(logs.String(), secretValue) || strings.Contains(string(body), secretValue) {
		t.Fatalf("authorization value leaked: logs=%q body=%q", logs.String(), body)
	}
	if !strings.Contains(logs.String(), "[REDACTED]") {
		t.Fatalf("expected a redacted log entry, got %q", logs.String())
	}
}

type wsTestClient struct {
	conn net.Conn
	br   *bufio.Reader
}

type wsFrame struct {
	op      byte
	payload []byte
}

func (c *wsTestClient) close() {
	_ = c.conn.Close()
}

func dialWebSocket(t *testing.T, server *mock.Server) *wsTestClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", server.Addr(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	handshake := fmt.Sprintf("GET /gateway HTTP/1.1\r\nHost: %s\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", server.Addr(), key)
	if _, err := io.WriteString(conn, handshake); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 101") {
		t.Fatalf("handshake status %q err=%v", status, err)
	}
	expectedAccept := base64.StdEncoding.EncodeToString(sha1Sum(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	foundAccept := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading handshake: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept:") {
			foundAccept = strings.TrimSpace(strings.TrimPrefix(line, "Sec-WebSocket-Accept:"))
		}
	}
	if foundAccept != expectedAccept {
		t.Fatalf("accept: got %q, want %q", foundAccept, expectedAccept)
	}
	return &wsTestClient{conn: conn, br: reader}
}

func sha1Sum(value string) []byte {
	sum := sha1.Sum([]byte(value))
	return sum[:]
}

func (c *wsTestClient) readFrame(t *testing.T) wsFrame {
	t.Helper()
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.br, header); err != nil {
		t.Fatalf("frame header: %v", err)
	}
	if header[1]&0x80 != 0 {
		t.Fatal("server-to-client frames must be unmasked")
	}
	length := int(header[1] & 0x7f)
	if length == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			t.Fatal(err)
		}
		length = int(ext[0])<<8 | int(ext[1])
	} else if length == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			t.Fatal(err)
		}
		length = int(uint64(ext[0])<<56 | uint64(ext[1])<<48 | uint64(ext[2])<<40 |
			uint64(ext[3])<<32 | uint64(ext[4])<<24 | uint64(ext[5])<<16 |
			uint64(ext[6])<<8 | uint64(ext[7]))
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(c.br, payload); err != nil {
			t.Fatalf("frame payload: %v", err)
		}
	}
	return wsFrame{op: header[0] & 0x0f, payload: payload}
}

func (c *wsTestClient) writeFrame(t *testing.T, opcode byte, payload []byte) {
	t.Helper()
	header := []byte{0x80 | opcode}
	switch n := len(payload); {
	case n < 126:
		header = append(header, 0x80|byte(n))
	case n <= 65535:
		header = append(header, 0x80|126, byte(n>>8), byte(n))
	default:
		header = append(header, 0x80|127)
		for shift := 56; shift >= 0; shift -= 8 {
			header = append(header, byte(uint64(n)>>uint(shift)))
		}
	}
	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	frame := append(header, mask[:]...)
	frame = append(frame, masked...)
	if _, err := c.conn.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func parseGatewayMessage(t *testing.T, frame wsFrame) map[string]any {
	t.Helper()
	if frame.op != 0x1 {
		t.Fatalf("expected text frame, got opcode %d", frame.op)
	}
	return decodeObject(t, frame.payload)
}

func TestWebSocketHandshakeHelloReadyMessageAndHeartbeat(t *testing.T) {
	server := newTestServer(t)
	client := dialWebSocket(t, server)
	defer client.close()

	hello := client.readFrame(t)
	if hello.op != 0x1 || string(hello.payload) != `{"op":10,"d":{"heartbeat_interval":41250}}` {
		t.Fatalf("HELLO mismatch: opcode=%d payload=%q", hello.op, hello.payload)
	}

	client.writeFrame(t, 0x1, []byte(`{"op":2,"d":{"token":"DUMMY_IDENTIFY_TOKEN"}}`))
	ready := parseGatewayMessage(t, client.readFrame(t))
	if ready["op"] != float64(0) || ready["s"] != float64(1) || ready["t"] != "READY" {
		t.Fatalf("READY mismatch: %v", ready)
	}
	message := parseGatewayMessage(t, client.readFrame(t))
	if message["op"] != float64(0) || message["s"] != float64(2) ||
		message["t"] != "MESSAGE_CREATE" {
		t.Fatalf("MESSAGE_CREATE mismatch: %v", message)
	}
	if !strings.Contains(string(mustMarshal(t, message)), "DUMMY_MESSAGE") {
		t.Fatalf("MESSAGE_CREATE payload is not synthetic: %v", message)
	}

	client.writeFrame(t, 0x1, []byte(`{"op":1,"d":null}`))
	ack := parseGatewayMessage(t, client.readFrame(t))
	if ack["op"] != float64(11) {
		t.Fatalf("HEARTBEAT_ACK mismatch: %v", ack)
	}
	if raw, ok := ack["d"]; !ok || raw != nil {
		t.Fatalf("HEARTBEAT_ACK must carry d:null: %v", ack)
	}

	client.writeFrame(t, 0x8, nil) // clean close
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestWebSocketExtendedFrameLengths(t *testing.T) {
	server := newTestServer(t)
	client := dialWebSocket(t, server)
	defer client.close()
	client.readFrame(t) // HELLO

	// 70k-byte payloads exercise the 64-bit length path in both directions.
	padding := strings.Repeat("x", 70000)
	client.writeFrame(t, 0x1, []byte(fmt.Sprintf(`{"op":2,"pad":%q}`, padding)))
	if ready := parseGatewayMessage(t, client.readFrame(t)); ready["t"] != "READY" {
		t.Fatalf("READY mismatch after large IDENTIFY: %v", ready)
	}
	client.readFrame(t) // MESSAGE_CREATE

	client.writeFrame(t, 0x1, []byte(fmt.Sprintf(`{"op":1,"pad":%q}`, padding)))
	if ack := parseGatewayMessage(t, client.readFrame(t)); ack["op"] != float64(11) {
		t.Fatalf("ACK mismatch after large HEARTBEAT: %v", ack)
	}
}

func TestServerLifecycleAndLoopbackOnly(t *testing.T) {
	server, err := mock.New(mock.Config{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(server.Addr(), "127.0.0.1:") || server.Port() <= 0 {
		t.Fatalf("server bound to unexpected address %s", server.Addr())
	}
	if _, err := mock.New(mock.Config{Port: -1}); err == nil {
		t.Fatal("expected error for invalid port")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := server.Run(); err != nil {
		t.Fatalf("Run after Close: %v", err)
	}
}
