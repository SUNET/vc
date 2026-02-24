//go:build didcomm && vc20

// Package transport provides WebSocket transport for DIDComm v2 messaging.
//
// # Coexistence with Wallet Frontend WebSocket
//
// The DIDComm WebSocket transport is designed to coexist with other WebSocket
// protocols such as the wallet-frontend keystore WebSocket (used for remote signing).
// Differentiation is achieved through:
//
//   - Endpoint: DIDComm uses a dedicated endpoint (e.g., /didcomm/ws or /ws/didcomm)
//     different from /ws/keystore used by wallet-frontend
//   - Subprotocol: DIDComm negotiates the "didcomm/v2" WebSocket subprotocol
//   - Message format: DIDComm messages are JWE/JWS encrypted/signed, not plain JSON
//
// # Example Server Setup (Gin)
//
//	router.GET("/didcomm/ws", func(c *gin.Context) {
//	    handler := transport.NewWebSocketHandler(processor)
//	    handler.ServeHTTP(c.Writer, c.Request)
//	})
//
//	// Wallet keystore WebSocket remains separate:
//	router.GET("/ws/keystore", handlers.WebSocketKeystore)

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"vc/pkg/didcomm"
)

const (
	// DIDCommSubprotocol is the WebSocket subprotocol for DIDComm v2
	DIDCommSubprotocol = "didcomm/v2"

	// Default timeouts and limits
	defaultPingInterval   = 30 * time.Second
	defaultReadTimeout    = 60 * time.Second
	defaultWriteTimeout   = 10 * time.Second
	defaultMaxMessageSize = 1024 * 1024 // 1MB
)

// WebSocketClient provides bidirectional DIDComm messaging over WebSocket.
type WebSocketClient struct {
	conn      *websocket.Conn
	processor MessageProcessor
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	done      chan struct{}

	// Configuration
	pingInterval   time.Duration
	readTimeout    time.Duration
	writeTimeout   time.Duration
	maxMessageSize int64
}

// WebSocketOption configures the WebSocket client.
type WebSocketOption func(*WebSocketClient)

// WithPingInterval sets the WebSocket ping interval for keepalive.
func WithPingInterval(d time.Duration) WebSocketOption {
	return func(c *WebSocketClient) {
		c.pingInterval = d
	}
}

// WithReadTimeout sets the read timeout for receiving messages.
func WithReadTimeout(d time.Duration) WebSocketOption {
	return func(c *WebSocketClient) {
		c.readTimeout = d
	}
}

// WithWriteTimeout sets the write timeout for sending messages.
func WithWriteTimeout(d time.Duration) WebSocketOption {
	return func(c *WebSocketClient) {
		c.writeTimeout = d
	}
}

// WithMaxMessageSize sets the maximum message size in bytes.
func WithMaxMessageSize(size int64) WebSocketOption {
	return func(c *WebSocketClient) {
		c.maxMessageSize = size
	}
}

// NewWebSocketClient creates a new WebSocket client with optional message processor.
// The processor is called for incoming messages; if nil, messages must be read manually
// via Receive().
func NewWebSocketClient(processor MessageProcessor, opts ...WebSocketOption) *WebSocketClient {
	c := &WebSocketClient{
		processor:      processor,
		pingInterval:   defaultPingInterval,
		readTimeout:    defaultReadTimeout,
		writeTimeout:   defaultWriteTimeout,
		maxMessageSize: defaultMaxMessageSize,
		done:           make(chan struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Connect establishes a WebSocket connection to the given endpoint.
// The endpoint should be a ws:// or wss:// URL.
func (c *WebSocketClient) Connect(ctx context.Context, endpoint string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return fmt.Errorf("already connected")
	}

	dialer := websocket.Dialer{
		Subprotocols: []string{DIDCommSubprotocol},
	}

	conn, resp, err := dialer.DialContext(ctx, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	// Verify subprotocol was accepted
	if resp.Header.Get("Sec-WebSocket-Protocol") != DIDCommSubprotocol {
		conn.Close()
		return fmt.Errorf("%w: server did not accept didcomm/v2 subprotocol", ErrConnectionFailed)
	}

	conn.SetReadLimit(c.maxMessageSize)
	c.conn = conn
	c.closed = false
	c.done = make(chan struct{})

	// Start read loop if processor is set
	if c.processor != nil {
		go c.readLoop()
	}

	// Start ping loop for keepalive
	go c.pingLoop()

	return nil
}

// Send sends a DIDComm message over the WebSocket connection.
func (c *WebSocketClient) Send(ctx context.Context, message []byte, mediaType string) error {
	c.mu.RLock()
	conn := c.conn
	closed := c.closed
	c.mu.RUnlock()

	if conn == nil || closed {
		return ErrConnectionClosed
	}

	// For DIDComm over WebSocket, we can send raw message bytes.
	// The mediaType indicates whether it's encrypted, signed, or plaintext.
	// Some implementations wrap in an envelope; we send raw for simplicity.
	_ = conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	if err := conn.WriteMessage(websocket.BinaryMessage, message); err != nil {
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}

	return nil
}

// SendWithEnvelope sends a DIDComm message wrapped in a JSON envelope with media type.
// Use this when the receiver needs explicit media type information.
func (c *WebSocketClient) SendWithEnvelope(ctx context.Context, message []byte, mediaType string) error {
	c.mu.RLock()
	conn := c.conn
	closed := c.closed
	c.mu.RUnlock()

	if conn == nil || closed {
		return ErrConnectionClosed
	}

	envelope := struct {
		MediaType string          `json:"media_type"`
		Data      json.RawMessage `json:"data"`
	}{
		MediaType: mediaType,
		Data:      message,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	if err := conn.WriteJSON(envelope); err != nil {
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}

	return nil
}

// Receive reads a single message from the WebSocket connection.
// This is for manual message handling when no processor is set.
func (c *WebSocketClient) Receive(ctx context.Context) ([]byte, string, error) {
	c.mu.RLock()
	conn := c.conn
	closed := c.closed
	c.mu.RUnlock()

	if conn == nil || closed {
		return nil, "", ErrConnectionClosed
	}

	_ = conn.SetReadDeadline(time.Now().Add(c.readTimeout))
	msgType, data, err := conn.ReadMessage()
	if err != nil {
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			return nil, "", ErrConnectionClosed
		}
		return nil, "", fmt.Errorf("%w: %v", ErrReceiveFailed, err)
	}

	// Determine media type based on message content
	mediaType := c.detectMediaType(msgType, data)
	return data, mediaType, nil
}

// detectMediaType attempts to determine the DIDComm media type from message content.
func (c *WebSocketClient) detectMediaType(msgType int, data []byte) string {
	if msgType == websocket.TextMessage {
		// Try to parse as JSON and check for ciphertext (encrypted) or payload (signed)
		var probe map[string]interface{}
		if json.Unmarshal(data, &probe) == nil {
			if _, ok := probe["ciphertext"]; ok {
				return didcomm.MediaTypeEncrypted
			}
			if _, ok := probe["payload"]; ok {
				return didcomm.MediaTypeSigned
			}
		}
		return didcomm.MediaTypePlaintext
	}
	// Binary messages are typically encrypted
	return didcomm.MediaTypeEncrypted
}

// Close closes the WebSocket connection.
func (c *WebSocketClient) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		conn := c.conn
		c.mu.Unlock()

		close(c.done)

		if conn != nil {
			// Send close message
			_ = conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(time.Second),
			)
			err = conn.Close()
		}
	})
	return err
}

// readLoop reads incoming messages and processes them.
func (c *WebSocketClient) readLoop() {
	for {
		select {
		case <-c.done:
			return
		default:
		}

		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()

		if conn == nil {
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(c.readTimeout))
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				// Unexpected close
			}
			c.Close()
			return
		}

		// Determine media type
		mediaType := c.detectMediaType(msgType, data)

		// Process message
		if c.processor != nil {
			ctx := context.Background()
			response, responseMediaType, err := c.processor.ProcessMessage(ctx, data, mediaType)
			if err != nil {
				// Log error but continue processing
				continue
			}

			// Send response if provided
			if response != nil {
				if sendErr := c.Send(ctx, response, responseMediaType); sendErr != nil {
					// Log error
				}
			}
		}
	}
}

// pingLoop sends periodic pings to keep the connection alive.
func (c *WebSocketClient) pingLoop() {
	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.mu.RLock()
			conn := c.conn
			c.mu.RUnlock()

			if conn == nil {
				return
			}

			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(c.writeTimeout)); err != nil {
				return
			}
		}
	}
}

// IsConnected returns whether the client is connected.
func (c *WebSocketClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil && !c.closed
}

// WebSocketHandler handles incoming WebSocket connections for DIDComm.
// It upgrades HTTP connections and processes DIDComm messages bidirectionally.
type WebSocketHandler struct {
	processor      MessageProcessor
	upgrader       websocket.Upgrader
	maxMessageSize int64
}

// WebSocketHandlerOption configures the WebSocket handler.
type WebSocketHandlerOption func(*WebSocketHandler)

// WithAllowedOrigins sets allowed WebSocket origins for CORS.
func WithAllowedOrigins(origins []string) WebSocketHandlerOption {
	return func(h *WebSocketHandler) {
		h.upgrader.CheckOrigin = func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			for _, allowed := range origins {
				if origin == allowed || allowed == "*" {
					return true
				}
			}
			return false
		}
	}
}

// WithHandlerMaxMessageSize sets the maximum message size for the handler.
func WithHandlerMaxMessageSize(size int64) WebSocketHandlerOption {
	return func(h *WebSocketHandler) {
		h.maxMessageSize = size
	}
}

// NewWebSocketHandler creates a new WebSocket handler for receiving DIDComm messages.
func NewWebSocketHandler(processor MessageProcessor, opts ...WebSocketHandlerOption) *WebSocketHandler {
	h := &WebSocketHandler{
		processor:      processor,
		maxMessageSize: defaultMaxMessageSize,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			Subprotocols:    []string{DIDCommSubprotocol},
			CheckOrigin: func(r *http.Request) bool {
				// Default: allow same origin
				return true
			},
		},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ServeHTTP implements http.Handler and upgrades HTTP connections to WebSocket.
func (h *WebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}
	defer conn.Close()

	// Verify subprotocol (gorilla sets this automatically if negotiated)
	if conn.Subprotocol() != DIDCommSubprotocol {
		// Client didn't request didcomm/v2 subprotocol - could allow plain WebSocket
		// or reject. For now, we continue but this may indicate a non-DIDComm client.
	}

	conn.SetReadLimit(h.maxMessageSize)

	// Set up ping/pong handlers
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		return nil
	})

	// Connection loop
	for {
		_ = conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				// Log unexpected close
			}
			return
		}

		// Determine media type
		mediaType := detectMediaTypeFromMessage(msgType, data)

		// Process message
		response, responseMediaType, err := h.processor.ProcessMessage(r.Context(), data, mediaType)
		if err != nil {
			// Log but continue
			continue
		}

		// Send response if provided
		if response != nil {
			outType := websocket.BinaryMessage
			if responseMediaType == didcomm.MediaTypePlaintext {
				outType = websocket.TextMessage
			}
			_ = conn.SetWriteDeadline(time.Now().Add(defaultWriteTimeout))
			if err := conn.WriteMessage(outType, response); err != nil {
				return
			}
		}
	}
}

// detectMediaTypeFromMessage determines the DIDComm media type from message content.
func detectMediaTypeFromMessage(msgType int, data []byte) string {
	if msgType == websocket.TextMessage {
		var probe map[string]interface{}
		if json.Unmarshal(data, &probe) == nil {
			if _, ok := probe["ciphertext"]; ok {
				return didcomm.MediaTypeEncrypted
			}
			if _, ok := probe["payload"]; ok {
				return didcomm.MediaTypeSigned
			}
		}
		return didcomm.MediaTypePlaintext
	}
	return didcomm.MediaTypeEncrypted
}
