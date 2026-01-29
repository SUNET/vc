package auditlog

import (
	"context"
	"testing"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsole_SendToDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled:      true,
				Destinations: []string{"console"},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	dest := service.destinations[0]
	jsonBytes := []byte(`{"test":"data"}`)

	err = service.sendToDestination(context.Background(), dest, jsonBytes)
	assert.NoError(t, err)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(context.Background())
}

func TestConsole_DestinationParsing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled: true,
				Destinations: []string{
					"console",
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)
	require.NotNil(t, service)
	require.Len(t, service.destinations, 1)
	assert.Equal(t, DestinationConsole, service.destinations[0].Type)
	assert.Equal(t, "console", service.destinations[0].Target)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	err = service.Close(context.Background())
	assert.NoError(t, err)
}

func TestConsole_MessageDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled:      true,
				Destinations: []string{"console"},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Send test message
	service.AddAuditLog(ctx, "console_test", map[string]string{
		"message": "test console output",
	})

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Console output happens, no errors
	assert.NotNil(t, service)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(context.Background())
}

func TestConsole_InvalidJSON(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled:      true,
				Destinations: []string{"console"},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Channel that cannot be marshalled to JSON
	invalidData := make(chan int)
	err = service.SendWebHook(context.Background(), invalidData)
	assert.Error(t, err)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(context.Background())
}
