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

func TestFile_SendToDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
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

	dest := service.destinations[0]
	jsonBytes := []byte(`{"test":"data"}`)

	err = service.sendToDestination(t.Context(), dest, jsonBytes)
	assert.NoError(t, err)

	// Verify file content
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "test")
	assert.Contains(t, string(content), "data")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}

func TestFile_FileSyncEveryWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit_sync.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled:          true,
				Destinations:     []string{logFile},
				FileSyncInterval: 0, // 0 = fsync every write
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), service.fileSyncInterval)

	dest := service.destinations[0]
	jsonBytes := []byte(`{"sync":"immediate"}`)

	err = service.writeToFile(dest, jsonBytes)
	assert.NoError(t, err)
	// dirty should remain false since sync happened immediately
	assert.False(t, dest.dirty)

	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "immediate")

	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}

func TestFile_DeferredSync(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit_deferred.log")

	cfg := &model.Cfg{
		Issuer: &model.Issuer{
			AuditLog: &model.AuditLog{
				Enabled:          true,
				Destinations:     []string{logFile},
				FileSyncInterval: 100 * time.Millisecond,
			},
		},
	}

	log := logger.NewSimple("test")
	service, err := New(ctx, cfg, log)
	require.NoError(t, err)
	assert.Equal(t, 100*time.Millisecond, service.fileSyncInterval)

	dest := service.destinations[0]
	jsonBytes := []byte(`{"sync":"deferred"}`)

	err = service.writeToFile(dest, jsonBytes)
	assert.NoError(t, err)
	// dirty should be true since sync is deferred
	assert.True(t, dest.dirty)

	// Wait for periodic sync to fire
	time.Sleep(250 * time.Millisecond)

	service.mu.Lock()
	isDirty := dest.dirty
	service.mu.Unlock()
	assert.False(t, isDirty, "periodic sync should have cleared dirty flag")

	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "deferred")

	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}



func TestFile_DestinationParsing(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
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
	err = service.Close(t.Context())
	assert.NoError(t, err)
}

func TestFile_InvalidPath(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
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

func TestFile_WriteToFile_NilFile(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
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

	dest := &Destination{
		Type:   DestinationFile,
		Target: "/tmp/test.log",
		File:   nil, // Nil file handle
	}

	jsonBytes := []byte(`{"test":"data"}`)
	err = service.writeToFile(dest, jsonBytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file handle is nil")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}

func TestFile_MultipleWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
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

	dest := service.destinations[0]

	// Write multiple times
	for i := 0; i < 10; i++ {
		jsonBytes := []byte(`{"iteration":` + string(rune(i+'0')) + `}`)
		err = service.writeToFile(dest, jsonBytes)
		assert.NoError(t, err)
	}

	// Verify all writes
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "iteration")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}

func TestFile_MessageDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
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
	err = service.Close(t.Context())
	assert.NoError(t, err)
}

func TestFile_ConcurrentWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
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

	// Send multiple audit logs concurrently
	for i := 0; i < 20; i++ {
		service.AddAuditLog(ctx, "concurrent_test", map[string]any{
			"iteration": i,
		})
	}

	// Wait for all processing
	time.Sleep(500 * time.Millisecond)

	// Verify file has entries
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "concurrent_test")
	assert.Contains(t, string(content), "iteration")

	// Clean up
	cancel()
	time.Sleep(100 * time.Millisecond)
	service.Close(t.Context())
}
