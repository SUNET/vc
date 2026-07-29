package auditlog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTP_SendWebHook_NoDestinations(t *testing.T) {
	ctx := t.Context()
	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: nil,
		},
	}

	log := logger.NewSimple("test")
	service, err := New(t.Context(), cfg, log)
	require.NoError(t, err)

	err = service.SendWebHook(ctx, map[string]string{"test": "data"})
	assert.NoError(t, err)

	// Clean up
	service.Close(t.Context()) // #nosec G104
}

func TestHTTP_SendToDestination_Webhook_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var data map[string]string
		err := json.NewDecoder(r.Body).Decode(&data)
		assert.NoError(t, err)
		assert.Equal(t, "data", data["test"])

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

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

	dest := service.destinations[0]
	jsonBytes := []byte(`{"test":"data"}`)

	err = service.sendToDestination(t.Context(), dest, jsonBytes)
	assert.NoError(t, err)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

func TestHTTP_SendToDestination_Webhook_Failure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Create test server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

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

	dest := service.destinations[0]
	jsonBytes := []byte(`{"test":"data"}`)

	err = service.sendToDestination(t.Context(), dest, jsonBytes)
	assert.Error(t, err)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

func TestHTTP_SendWebhook_InvalidURL(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable:       true,
				Destinations: []string{"console"},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	jsonBytes := []byte(`{"test":"data"}`)
	err = service.sendWebhook(t.Context(), "://invalid-url", jsonBytes)
	assert.Error(t, err)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

func TestHTTP_SendWebhook_Timeout(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Create test server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second) // Longer than timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable:       true,
				Destinations: []string{"console"},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	jsonBytes := []byte(`{"test":"data"}`)
	err = service.sendWebhook(t.Context(), server.URL, jsonBytes)
	assert.Error(t, err)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

func TestHTTP_DestinationParsing(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable: true,
				Destinations: []string{
					"http://example.com/webhook",
					"https://example.com/webhook2",
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)
	require.NotNil(t, service)
	require.Len(t, service.destinations, 2)
	assert.Equal(t, DestinationWebhook, service.destinations[0].Type)
	assert.Equal(t, "http://example.com/webhook", service.destinations[0].Target)
	assert.Equal(t, DestinationWebhook, service.destinations[1].Type)
	assert.Equal(t, "https://example.com/webhook2", service.destinations[1].Target)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

func TestHTTP_MessageDelivery(t *testing.T) {
	receivedCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCount++
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

	// Send audit log
	service.AddAuditLog(ctx, "webhook_test", map[string]string{
		"message": "test webhook",
	})

	// Wait for delivery
	time.Sleep(300 * time.Millisecond)

	assert.Equal(t, 1, receivedCount, "Webhook should have been called once")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}

func TestHTTP_QueueFull(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

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

	// Fill the queue beyond capacity
	for i := range 150 { // More than buffer size of 100
		err = service.SendWebHook(t.Context(), map[string]int{"iteration": i})
		// Should not error even when queue is full (messages are dropped)
		assert.NoError(t, err)
	}

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context()) // #nosec G104
}
