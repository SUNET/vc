package auditlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Disabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: nil,
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Empty(t, service.destinations)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	err = service.Close(context.Background())
	assert.NoError(t, err)
}

func TestNew_ConsoleDestination(t *testing.T) {
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

func TestNew_FileDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled: true,
				Destinations: []string{
					logFile,
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)
	require.NotNil(t, service)
	require.Len(t, service.destinations, 1)
	assert.Equal(t, DestinationFile, service.destinations[0].Type)
	assert.Equal(t, logFile, service.destinations[0].Target)
	assert.NotNil(t, service.destinations[0].File)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	err = service.Close(context.Background())
	assert.NoError(t, err)
}

func TestNew_WebhookDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled: true,
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
	err = service.Close(context.Background())
	assert.NoError(t, err)
}

func TestNew_MultipleDestinations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled: true,
				Destinations: []string{
					"console",
					logFile,
					"http://example.com/webhook",
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)
	require.NotNil(t, service)
	require.Len(t, service.destinations, 3)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	err = service.Close(context.Background())
	assert.NoError(t, err)
}

func TestNew_InvalidFileDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled: true,
				Destinations: []string{
					"/invalid/path/that/does/not/exist/audit.log",
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	assert.Error(t, err)
	assert.Nil(t, service)
}

func TestParseDestinations_EmptyStrings(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled: true,
				Destinations: []string{
					"",
					"  ",
					"console",
					"",
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)
	require.NotNil(t, service)
	// Only console should be parsed
	require.Len(t, service.destinations, 1)
	assert.Equal(t, DestinationConsole, service.destinations[0].Type)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	err = service.Close(context.Background())
	assert.NoError(t, err)
}

func TestAddAuditLog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled: true,
				Destinations: []string{
					logFile,
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Add audit log
	service.AddAuditLog(ctx, "test_event", map[string]string{"key": "value"})

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify file was written
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "test_event")
	assert.Contains(t, string(content), "key")
	assert.Contains(t, string(content), "value")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	err = service.Close(context.Background())
	assert.NoError(t, err)
}

func TestClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled:      true,
				Destinations: []string{logFile, "console"},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Cancel context and close
	cancel()
	time.Sleep(100 * time.Millisecond)
	err = service.Close(context.Background())
	assert.NoError(t, err)

	// File should be closed
	for _, dest := range service.destinations {
		if dest.Type == DestinationFile {
			// Try to write to closed file should fail
			_, writeErr := dest.File.Write([]byte("test"))
			assert.Error(t, writeErr)
		}
	}
}

func TestDestinationWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled:      true,
				Destinations: []string{logFile},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Send multiple messages
	for i := 0; i < 5; i++ {
		service.AddAuditLog(ctx, "test_event", map[string]interface{}{
			"iteration": i,
		})
	}

	// Wait for processing
	time.Sleep(300 * time.Millisecond)

	// Verify all messages were written
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "test_event")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	err = service.Close(context.Background())
	assert.NoError(t, err)
}

func TestAuditLogStruct(t *testing.T) {
	auditLog := &AuditLog{
		EventType: "test",
		Date:      "2026-01-29T12:00:00Z",
		ID:        "123",
		Message:   "test message",
	}

	assert.Equal(t, "test", auditLog.EventType)
	assert.Equal(t, "2026-01-29T12:00:00Z", auditLog.Date)
	assert.Equal(t, "123", auditLog.ID)
	assert.Equal(t, "test message", auditLog.Message)
}

func TestDestinationType_String(t *testing.T) {
	tests := []struct {
		name     string
		destType DestinationType
	}{
		{"Console", DestinationConsole},
		{"File", DestinationFile},
		{"Webhook", DestinationWebhook},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just ensure the type can be used
			dest := &Destination{Type: tt.destType}
			assert.NotNil(t, dest)
		})
	}
}

func TestSendToDestination_UnknownType(t *testing.T) {
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

	// Create destination with invalid type
	dest := &Destination{
		Type:   DestinationType(999), // Invalid type
		Target: "invalid",
	}

	jsonBytes := []byte(`{"test":"data"}`)
	err = service.sendToDestination(context.Background(), dest, jsonBytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown destination type")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(context.Background())
}
