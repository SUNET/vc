package auditlog

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_WebhookDelivery tests actual webhook delivery using httptest
func TestIntegration_WebhookDelivery(t *testing.T) {
	// Track received webhooks
	var mu sync.Mutex
	var receivedPayloads []map[string]any

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read body
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		// Parse JSON
		var payload map[string]any
		err = json.Unmarshal(body, &payload)
		assert.NoError(t, err)

		// Store received payload
		mu.Lock()
		receivedPayloads = append(receivedPayloads, payload)
		mu.Unlock()

		t.Logf("Received webhook: event=%s, id=%s", payload["event"], payload["id"])

		// Return success
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Configure audit log to send to test server
	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable: true,
				Destinations: []string{
					server.URL,
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Send test audit log
	testMessage := map[string]any{
		"user":   "test_user",
		"action": "test_action",
		"data":   "test_data",
	}
	service.AddAuditLog(ctx, "integration_test", testMessage)

	// Wait for delivery
	time.Sleep(500 * time.Millisecond)

	// Verify webhook was received
	mu.Lock()
	require.Len(t, receivedPayloads, 1)
	payload := receivedPayloads[0]
	mu.Unlock()

	// Verify payload structure
	assert.Equal(t, "integration_test", payload["event"])
	assert.NotEmpty(t, payload["id"])
	assert.NotEmpty(t, payload["date"])

	message, ok := payload["message"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "test_user", message["user"])
	assert.Equal(t, "test_action", message["action"])
	assert.Equal(t, "test_data", message["data"])

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

// TestIntegration_MultipleWebhooks tests sending to multiple webhook endpoints
func TestIntegration_MultipleWebhooks(t *testing.T) {
	// Track received webhooks per server
	type serverData struct {
		mu       sync.Mutex
		payloads []map[string]any
	}

	server1Data := &serverData{}
	server2Data := &serverData{}

	// Create two test servers
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		json.Unmarshal(body, &payload) // #nosec G104

		server1Data.mu.Lock()
		server1Data.payloads = append(server1Data.payloads, payload)
		server1Data.mu.Unlock()

		t.Logf("Server 1 received: %s", payload["event"])
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		json.Unmarshal(body, &payload) // #nosec G104

		server2Data.mu.Lock()
		server2Data.payloads = append(server2Data.payloads, payload)
		server2Data.mu.Unlock()

		t.Logf("Server 2 received: %s", payload["event"])
		w.WriteHeader(http.StatusOK)
	}))
	defer server2.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Configure audit log with both servers
	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable: true,
				Destinations: []string{
					server1.URL,
					server2.URL,
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Send audit log
	service.AddAuditLog(ctx, "multi_webhook_test", map[string]string{
		"test": "multiple_webhooks",
	})

	// Wait for delivery
	time.Sleep(500 * time.Millisecond)

	// Verify both servers received the webhook
	server1Data.mu.Lock()
	assert.Len(t, server1Data.payloads, 1)
	assert.Equal(t, "multi_webhook_test", server1Data.payloads[0]["event"])
	server1Data.mu.Unlock()

	server2Data.mu.Lock()
	assert.Len(t, server2Data.payloads, 1)
	assert.Equal(t, "multi_webhook_test", server2Data.payloads[0]["event"])
	server2Data.mu.Unlock()

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

// TestIntegration_HighVolumeWebhooks tests sending many webhooks rapidly
func TestIntegration_HighVolumeWebhooks(t *testing.T) {
	var mu sync.Mutex
	receivedCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable: true,
				Destinations: []string{
					server.URL,
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Send 50 webhooks rapidly
	const webhookCount = 50
	start := time.Now()

	for i := range webhookCount {
		service.AddAuditLog(ctx, "high_volume_test", map[string]int{
			"iteration": i,
		})
	}

	// Wait for all deliveries
	time.Sleep(2 * time.Second)
	duration := time.Since(start)

	// Verify all webhooks were received
	mu.Lock()
	t.Logf("Received %d/%d webhooks in %v (%.2f webhooks/sec)",
		receivedCount, webhookCount, duration, float64(receivedCount)/duration.Seconds())
	mu.Unlock()

	// Should receive most webhooks (some may be dropped if queue fills up)
	assert.GreaterOrEqual(t, receivedCount, webhookCount-10, "Should receive at least 40/50 webhooks")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

// TestIntegration_WebhookRetryOnFailure tests behavior when webhook fails
func TestIntegration_WebhookRetryOnFailure(t *testing.T) {
	attemptCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attemptCount++
		currentAttempt := attemptCount
		mu.Unlock()

		// Fail first 2 attempts, succeed on 3rd
		if currentAttempt < 3 {
			t.Logf("Attempt %d: returning error", currentAttempt)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		t.Logf("Attempt %d: returning success", currentAttempt)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable: true,
				Destinations: []string{
					server.URL,
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Send audit logs - each failed webhook will be logged but not retried
	for i := range 3 {
		service.AddAuditLog(ctx, "retry_test", map[string]int{
			"attempt": i + 1,
		})
		time.Sleep(200 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	// Verify attempts were made
	mu.Lock()
	t.Logf("Total webhook attempts: %d", attemptCount)
	assert.Equal(t, 3, attemptCount, "Should have made 3 attempts (no automatic retry)")
	mu.Unlock()

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

// TestIntegration_WebhookPayloadStructure verifies the exact webhook payload format
func TestIntegration_WebhookPayloadStructure(t *testing.T) {
	var receivedPayload map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedPayload) // #nosec G104
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable:       true,
				Destinations: []string{server.URL},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Send audit log with specific structure
	testMessage := map[string]any{
		"user_id":     "user-123",
		"action_type": "credential_issued",
		"details": map[string]string{
			"credential_type": "diploma",
			"credential_id":   "cred-456",
		},
	}
	service.AddAuditLog(ctx, "credential_event", testMessage)

	time.Sleep(500 * time.Millisecond)

	// Verify exact payload structure
	require.NotNil(t, receivedPayload)
	assert.Equal(t, "credential_event", receivedPayload["event"])
	assert.NotEmpty(t, receivedPayload["id"], "Should have UUID")
	assert.NotEmpty(t, receivedPayload["date"], "Should have RFC3339 timestamp")

	// Verify message structure
	message, ok := receivedPayload["message"].(map[string]any)
	require.True(t, ok, "Message should be an object")
	assert.Equal(t, "user-123", message["user_id"])
	assert.Equal(t, "credential_issued", message["action_type"])

	details, ok := message["details"].(map[string]any)
	require.True(t, ok, "Details should be an object")
	assert.Equal(t, "diploma", details["credential_type"])
	assert.Equal(t, "cred-456", details["credential_id"])

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

// TestIntegration_MixedDestinations tests console, file, and webhook together
func TestIntegration_MixedDestinations(t *testing.T) {
	var webhookReceived bool
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		webhookReceived = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := tmpDir + "/audit.log"

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable: true,
				Destinations: []string{
					"console",
					logFile,
					server.URL,
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Send audit log
	service.AddAuditLog(ctx, "mixed_destinations", map[string]string{
		"test": "all_destinations",
	})

	time.Sleep(500 * time.Millisecond)

	// Verify webhook received
	mu.Lock()
	assert.True(t, webhookReceived, "Webhook should have been received")
	mu.Unlock()

	// Verify file written
	content, err := os.ReadFile(logFile) // #nosec G304
	require.NoError(t, err)
	assert.Contains(t, string(content), "mixed_destinations")
	assert.Contains(t, string(content), "all_destinations")

	t.Log("✅ Message delivered to console, file, and webhook")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}
