// Package mock provides a fully local, synthetic Discord-like REST and
// WebSocket server. It never performs outbound requests.
package mock

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Config configures the mock server. A zero value is valid and asks the OS
// for a free loopback port. Host is always forced to 127.0.0.1.
type Config struct {
	Port int `json:"port"`
}

// Server wraps an http.Server and its loopback-only listener.
type Server struct {
	httpServer *http.Server
	listener   net.Listener
	port       int

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	closeOnce sync.Once
	closeErr  error
}

// New binds a loopback listener and prepares all routes. Serving starts in Run.
func New(cfg Config) (*Server, error) {
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("invalid mock port %d", cfg.Port)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("listen on 127.0.0.1: %w", err)
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("unexpected listener address %q", listener.Addr())
	}
	s := &Server{
		listener: listener,
		port:     addr.Port,
		conns:    make(map[net.Conn]struct{}),
	}
	s.httpServer = &http.Server{
		Handler:           http.HandlerFunc(s.serveHTTP),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// Addr returns the bound address in host:port form.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Port returns the bound TCP port (useful when Config.Port was 0).
func (s *Server) Port() int {
	return s.port
}

// Run serves requests until Close is called. A clean shutdown returns nil.
func (s *Server) Run() error {
	err := s.httpServer.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}

// Close stops the server and any hijacked WebSocket connections. It is safe
// to call more than once or before Run.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		conns := make([]net.Conn, 0, len(s.conns))
		for conn := range s.conns {
			conns = append(conns, conn)
		}
		s.mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		s.closeErr = s.httpServer.Close()
		_ = s.listener.Close()
	})
	return s.closeErr
}

func (s *Server) track(conn net.Conn) {
	s.mu.Lock()
	s.conns[conn] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	// Authorization values are never logged or echoed, only redacted.
	if r.Header.Get("Authorization") != "" {
		log.Printf("dsmock %s %s Authorization: [REDACTED]", r.Method, r.URL.Path)
	}

	if r.URL.Path == "/gateway" && r.Method == http.MethodGet {
		s.handleWebSocket(w, r)
		return
	}

	switch {
	case r.URL.Path == "/health" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, `{"ok":true}`)
	case r.URL.Path == "/api/v10/gateway" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, fmt.Sprintf(
			`{"url":"ws://127.0.0.1:%d/gateway","shards":1}`, s.port))
	case r.URL.Path == "/api/v10/users/@me" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK,
			`{"id":"100000000000000001","username":"DUMMY_USER","bot":true}`)
	case r.URL.Path == "/api/v10/guilds/100000000000000002" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK,
			`{"id":"100000000000000002","name":"DUMMY_GUILD"}`)
	case r.URL.Path == "/api/v10/channels/100000000000000003/messages" && r.Method == http.MethodPost:
		writeJSON(w, http.StatusCreated,
			`{"id":"100000000000000005","content":"DUMMY_MESSAGE"}`)
	case r.URL.Path == "/api/v10/rate-limited" && r.Method == http.MethodGet:
		w.Header().Set("Retry-After", "1")
		w.Header().Set("X-RateLimit-Limit", "5")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Unix()+1, 10))
		writeJSON(w, http.StatusTooManyRequests,
			`{"message":"DUMMY_RATE_LIMIT","retry_after":1}`)
	case r.URL.Path == "/api/v10/oauth2/token" && r.Method == http.MethodPost:
		writeJSON(w, http.StatusOK,
			`{"access_token":"DUMMY_ACCESS_TOKEN","token_type":"Bearer","expires_in":3600,"scope":"identify"}`)
	case r.URL.Path == "/api/v10/webhooks/100000000000000004/DUMMYWEBHOOK" && r.Method == http.MethodPost:
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/api/v10/forbidden" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusForbidden,
			`{"message":"DUMMY_FORBIDDEN","code":50013}`)
	default:
		writeJSON(w, http.StatusNotFound, `{"message":"DUMMY_NOT_FOUND"}`)
	}
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !headerTokenContains(r.Header.Get("Upgrade"), "websocket") ||
		!headerTokenContains(r.Header.Get("Connection"), "upgrade") || key == "" {
		w.Header().Set("Connection", "close")
		http.Error(w, "invalid websocket handshake", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	s.track(conn)
	defer s.untrack(conn)
	defer conn.Close()

	accept := base64.StdEncoding.EncodeToString(sha1Sum(key + websocketGUID))
	if _, err := fmt.Fprintf(rw.Writer,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return
	}
	if err := rw.Writer.Flush(); err != nil {
		return
	}
	if err := writeFrame(rw.Writer, 0x1, []byte(`{"op":10,"d":{"heartbeat_interval":41250}}`)); err != nil {
		return
	}
	if err := rw.Writer.Flush(); err != nil {
		return
	}

	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(rw.Reader, header); err != nil {
			return
		}
		opcode := header[0] & 0x0f
		masked := header[1]&0x80 != 0
		length := uint64(header[1] & 0x7f)
		if length == 126 {
			ext := make([]byte, 2)
			if _, err := io.ReadFull(rw.Reader, ext); err != nil {
				return
			}
			length = uint64(binary.BigEndian.Uint16(ext))
		} else if length == 127 {
			ext := make([]byte, 8)
			if _, err := io.ReadFull(rw.Reader, ext); err != nil {
				return
			}
			length = binary.BigEndian.Uint64(ext)
		}
		if length > 1<<20 {
			return
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(rw.Reader, mask[:]); err != nil {
				return
			}
		}
		payload := make([]byte, length)
		if len(payload) > 0 {
			if _, err := io.ReadFull(rw.Reader, payload); err != nil {
				return
			}
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}

		switch opcode {
		case 0x8: // CLOSE
			_ = writeFrame(rw.Writer, 0x8, nil)
			_ = rw.Writer.Flush()
			return
		case 0x9: // PING
			if err := writeFrame(rw.Writer, 0xA, payload); err != nil {
				return
			}
			if err := rw.Writer.Flush(); err != nil {
				return
			}
		case 0x1: // TEXT
			var message struct {
				Op int `json:"op"`
			}
			if err := json.Unmarshal(payload, &message); err != nil {
				continue
			}
			switch message.Op {
			case 2: // IDENTIFY
				frames := []string{
					`{"op":0,"s":1,"t":"READY","d":{"user":{"id":"100000000000000001","username":"DUMMY_USER"}}}`,
					`{"op":0,"s":2,"t":"MESSAGE_CREATE","d":{"id":"100000000000000005","content":"DUMMY_MESSAGE"}}`,
				}
				for _, frame := range frames {
					if err := writeFrame(rw.Writer, 0x1, []byte(frame)); err != nil {
						return
					}
				}
			case 1: // HEARTBEAT
				if err := writeFrame(rw.Writer, 0x1, []byte(`{"op":11,"d":null}`)); err != nil {
					return
				}
			}
			if err := rw.Writer.Flush(); err != nil {
				return
			}
		}
	}
}

// writeFrame writes an unmasked server frame with 7/16/64-bit length encoding.
func writeFrame(w io.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}
	switch n := len(payload); {
	case n < 126:
		header = append(header, byte(n))
	case n <= 65535:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		header = append(header, 127)
		for shift := 56; shift >= 0; shift -= 8 {
			header = append(header, byte(uint64(n)>>uint(shift)))
		}
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

func sha1Sum(value string) []byte {
	sum := sha1.Sum([]byte(value))
	return sum[:]
}

func headerTokenContains(header, want string) bool {
	for _, token := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(token), want) {
			return true
		}
	}
	return false
}
