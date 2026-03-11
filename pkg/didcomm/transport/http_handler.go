package transport

import (
	"context"
	"io"
	"net/http"
	"strings"

	"vc/pkg/didcomm"
)

// MessageProcessor processes incoming DIDComm messages.
type MessageProcessor interface {
	// ProcessMessage processes an incoming message and optionally returns a response.
	ProcessMessage(ctx context.Context, message []byte, mediaType string) (response []byte, responseMediaType string, err error)
}

// HTTPHandler handles incoming DIDComm messages over HTTP.
type HTTPHandler struct {
	processor    MessageProcessor
	allowedTypes []string
}

// HTTPHandlerOption configures the HTTP handler.
type HTTPHandlerOption func(*HTTPHandler)

// WithAllowedContentTypes sets the allowed content types.
func WithAllowedContentTypes(types ...string) HTTPHandlerOption {
	return func(h *HTTPHandler) {
		h.allowedTypes = types
	}
}

// NewHTTPHandler creates a new HTTP handler for receiving DIDComm messages.
func NewHTTPHandler(processor MessageProcessor, opts ...HTTPHandlerOption) *HTTPHandler {
	h := &HTTPHandler{
		processor: processor,
		allowedTypes: []string{
			didcomm.MediaTypeEncrypted,
			didcomm.MediaTypeSigned,
			didcomm.MediaTypePlaintext,
		},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ServeHTTP implements http.Handler.
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if !h.isAllowedContentType(contentType) {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return
	}

	// Process the message
	response, responseMediaType, err := h.processor.ProcessMessage(r.Context(), body, contentType)
	if err != nil {
		// Log error but don't expose details
		http.Error(w, "Message processing failed", http.StatusInternalServerError)
		return
	}

	// If no response, return 202 Accepted
	if response == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Return the response
	w.Header().Set("Content-Type", responseMediaType)
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// isAllowedContentType checks if a content type is allowed.
func (h *HTTPHandler) isAllowedContentType(contentType string) bool {
	// Handle content types with parameters (e.g., "application/json; charset=utf-8")
	baseType := contentType
	if idx := strings.Index(contentType, ";"); idx != -1 {
		baseType = strings.TrimSpace(contentType[:idx])
	}

	for _, allowed := range h.allowedTypes {
		if strings.EqualFold(baseType, allowed) {
			return true
		}
	}
	return false
}
