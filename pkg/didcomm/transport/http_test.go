package transport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/didcomm"
)

func TestHTTPClient_Send(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != didcomm.MediaTypeEncrypted {
			t.Errorf("Content-Type = %s, want %s", contentType, didcomm.MediaTypeEncrypted)
		}

		body, _ := io.ReadAll(r.Body)
		if string(body) != "test-message" {
			t.Errorf("body = %s, want test-message", string(body))
		}

		// Return response
		w.Header().Set("Content-Type", didcomm.MediaTypePlaintext)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response-message"))
	}))
	defer server.Close()

	// Test send
	client := NewHTTPClient()
	resp, err := client.Send(context.Background(), SendRequest{
		Endpoint:  server.URL,
		Message:   []byte("test-message"),
		MediaType: didcomm.MediaTypeEncrypted,
	})

	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if string(resp.Body) != "response-message" {
		t.Errorf("Body = %s, want response-message", string(resp.Body))
	}
}

func TestHTTPClient_Send_NoEndpoint(t *testing.T) {
	client := NewHTTPClient()
	_, err := client.Send(context.Background(), SendRequest{
		Message: []byte("test"),
	})

	if err == nil {
		t.Error("expected error for empty endpoint")
	}
}

func TestHTTPClient_SendMessage_Accepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := NewHTTPClient()
	resp, err := client.SendMessage(context.Background(), server.URL, []byte("test"), didcomm.MediaTypeEncrypted)

	if err != nil {
		t.Fatalf("SendMessage() error = %v", err)
	}

	if resp != nil {
		t.Errorf("expected nil response for 202 Accepted")
	}
}

// mockProcessor implements MessageProcessor for testing.
type mockProcessor struct {
	response     []byte
	responseType string
	err          error
}

func (p *mockProcessor) ProcessMessage(ctx context.Context, message []byte, mediaType string) ([]byte, string, error) {
	if p.err != nil {
		return nil, "", p.err
	}
	return p.response, p.responseType, nil
}

func TestHTTPHandler_ServeHTTP(t *testing.T) {
	processor := &mockProcessor{
		response:     []byte("response"),
		responseType: didcomm.MediaTypePlaintext,
	}

	handler := NewHTTPHandler(processor)

	// Create test request
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"test":"message"}`))
	req.Header.Set("Content-Type", didcomm.MediaTypeEncrypted)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if rec.Header().Get("Content-Type") != didcomm.MediaTypePlaintext {
		t.Errorf("Content-Type = %s, want %s", rec.Header().Get("Content-Type"), didcomm.MediaTypePlaintext)
	}

	if rec.Body.String() != "response" {
		t.Errorf("body = %s, want response", rec.Body.String())
	}
}

func TestHTTPHandler_ServeHTTP_NoResponse(t *testing.T) {
	processor := &mockProcessor{
		response: nil,
	}

	handler := NewHTTPHandler(processor)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"test":"message"}`))
	req.Header.Set("Content-Type", didcomm.MediaTypeEncrypted)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d (Accepted)", rec.Code, http.StatusAccepted)
	}
}

func TestHTTPHandler_ServeHTTP_WrongMethod(t *testing.T) {
	handler := NewHTTPHandler(&mockProcessor{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHTTPHandler_ServeHTTP_UnsupportedMediaType(t *testing.T) {
	handler := NewHTTPHandler(&mockProcessor{})

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("test"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnsupportedMediaType)
	}
}

func TestHTTPHandler_ServeHTTP_EmptyBody(t *testing.T) {
	handler := NewHTTPHandler(&mockProcessor{})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", didcomm.MediaTypeEncrypted)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHTTPClient_Options(t *testing.T) {
	client := NewHTTPClient(
		WithUserAgent("Test/1.0"),
	)

	if client.userAgent != "Test/1.0" {
		t.Errorf("userAgent = %s, want Test/1.0", client.userAgent)
	}
}
