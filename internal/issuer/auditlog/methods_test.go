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

func TestAddAuditLog_GeneratesID(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable:       true,
				Destinations: []string{logFile},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Add audit log
	service.AddAuditLog(ctx, "test_event", "test message")

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify file was written with UUID
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "test_event")
	assert.Contains(t, string(content), "test message")
	// Should contain UUID-like ID
	assert.Regexp(t, `"id":"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"`, string(content))
	// Should contain RFC3339 timestamp
	assert.Contains(t, string(content), "T")
	assert.Contains(t, string(content), "Z")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}

func TestAddAuditLog_ComplexMessage(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable:       true,
				Destinations: []string{logFile},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Add audit log with complex message
	message := map[string]any{
		"user":   "john_doe",
		"action": "credential_issued",
		"details": map[string]any{
			"type": "diploma",
			"id":   "12345",
		},
	}
	service.AddAuditLog(ctx, "credential_issued", message)

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify file content
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "credential_issued")
	assert.Contains(t, string(content), "john_doe")
	assert.Contains(t, string(content), "diploma")
	assert.Contains(t, string(content), "12345")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}

func TestProcessAuditLog_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable:       true,
				Destinations: []string{logFile},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Add some audit logs
	for i := range 3 {
		service.AddAuditLog(ctx, "test_event", map[string]int{"iteration": i})
	}

	// Wait a bit for processing
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for graceful shutdown
	time.Sleep(200 * time.Millisecond)

	// Close service
	err = service.Close(t.Context())
	assert.NoError(t, err)
}

func TestProcessAuditLog_ErrorHandling(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Use invalid webhook URL to trigger errors
	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable: true,
				Destinations: []string{
					"http://localhost:99999", // Invalid port
				},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Add audit log - should not panic even if webhook fails
	service.AddAuditLog(ctx, "test_event", "test message")

	// Wait for processing attempt
	time.Sleep(200 * time.Millisecond)

	// Service should still be running
	assert.NotNil(t, service)

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}

func TestProcessAuditLog_MultipleMessages(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable:       true,
				Destinations: []string{logFile},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Add multiple audit logs rapidly
	for i := range 20 {
		service.AddAuditLog(ctx, "rapid_event", map[string]any{
			"sequence": i,
			"data":     "test data",
		})
	}

	// Wait for all processing
	time.Sleep(500 * time.Millisecond)

	// Verify file has multiple entries
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "rapid_event")
	assert.Contains(t, string(content), "sequence")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}

func TestAddAuditLog_NilMessage(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enable:       true,
				Destinations: []string{logFile},
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)

	// Add audit log with nil message (should not panic)
	service.AddAuditLog(ctx, "test_event", nil)

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify file was written
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "test_event")
	assert.Contains(t, string(content), "null")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}
