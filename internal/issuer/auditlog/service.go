package auditlog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

// DestinationType represents the type of audit log destination
type DestinationType int

const (
	DestinationConsole DestinationType = iota
	DestinationFile
	DestinationWebhook
)

// Destination represents a parsed audit log destination
type Destination struct {
	Type    DestinationType
	Target  string             // file path or webhook URL
	File    *os.File           // open file handle for file destinations
	msgChan chan []byte        // message queue for this destination
	cancel  context.CancelFunc // cancel function to stop worker
	dirty   bool               // true when writes have occurred since last sync
}

// AuditLog holds the request data for the SendWebHook method
type AuditLog struct {
	EventType string `json:"event"`
	Date      string `json:"date"`
	ID        string `json:"id"`
	Message   any    `json:"message"`
}

// Service holds auditlog service
type Service struct {
	cfg              *model.Cfg
	log              *logger.Log
	auditLogChan     chan *AuditLog
	wg               sync.WaitGroup
	cancel           context.CancelFunc // cancels processAuditLog
	destinations     []*Destination     // pre-parsed destinations
	mu               sync.Mutex         // mutex for file operations
	done             chan struct{}      // closed on shutdown to prevent sends
	closeOnce        sync.Once          // ensures done is closed exactly once
	fileSyncInterval time.Duration      // file destinations: 0 = fsync every write, >0 = periodic batched fsync
}

// New creates a new auditlog service
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	service := &Service{
		cfg:          cfg,
		log:          log.New("auditlog"),
		auditLogChan: make(chan *AuditLog, 100), // buffered channel
		done:         make(chan struct{}),
	}

	// Parse and prepare destinations
	if cfg.Issuer != nil && cfg.Issuer.AuditLog != nil && cfg.Issuer.AuditLog.Enable {
		service.fileSyncInterval = cfg.Issuer.AuditLog.FileSyncInterval

		var err error
		service.destinations, err = service.parseDestinations(cfg.Issuer.AuditLog.Destinations)
		if err != nil {
			return nil, fmt.Errorf("failed to parse audit log destinations: %w", err)
		}
		service.log.Info("Audit log enabled", "destinations", len(service.destinations),
			"file_sync_interval", service.fileSyncInterval)

		// Start worker for each destination
		for _, dest := range service.destinations {
			workerCtx, cancel := context.WithCancel(ctx)
			dest.cancel = cancel
			dest.msgChan = make(chan []byte, 100) // buffered channel per destination
			service.wg.Add(1)
			go service.destinationWorker(workerCtx, dest)

			// Start periodic sync goroutine for file destinations
			if dest.Type == DestinationFile && service.fileSyncInterval > 0 {
				service.wg.Add(1)
				go service.periodicSync(workerCtx, dest)
			}
		}
	} else {
		service.log.Info("Audit log disabled")
	}

	processCtx, processCancel := context.WithCancel(ctx)
	service.cancel = processCancel
	service.wg.Add(1)
	go service.processAuditLog(processCtx)

	service.log.Info("Started")

	return service, nil
}

// parseDestinations parses destination strings into Destination structs
func (s *Service) parseDestinations(dests []string) ([]*Destination, error) {
	var destinations []*Destination

	for _, dest := range dests {
		dest = strings.TrimSpace(dest)
		if dest == "" {
			continue
		}

		// Console
		if dest == "console" {
			destinations = append(destinations, &Destination{
				Type:   DestinationConsole,
				Target: "console",
			})
			s.log.Info("Audit log destination: console")
			continue
		}

		// Webhook (HTTP/HTTPS)
		if strings.HasPrefix(dest, "http://") || strings.HasPrefix(dest, "https://") {
			destinations = append(destinations, &Destination{
				Type:   DestinationWebhook,
				Target: dest,
			})
			s.log.Info("Audit log destination: webhook", "url", dest)
			continue
		}

		// File path
		// Open file in append mode, create if not exists
		f, err := os.OpenFile(filepath.Clean(dest), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log file %s: %w", dest, err)
		}
		destinations = append(destinations, &Destination{
			Type:   DestinationFile,
			Target: dest,
			File:   f,
		})
		s.log.Info("Audit log destination: file", "path", dest)
	}

	return destinations, nil
}

// destinationWorker processes messages for a specific destination
func (s *Service) destinationWorker(ctx context.Context, dest *Destination) {
	defer s.wg.Done()

	var destType string
	switch dest.Type {
	case DestinationConsole:
		destType = "console"
	case DestinationFile:
		destType = "file"
	case DestinationWebhook:
		destType = "webhook"
	}

	s.log.Info("Destination worker started", "type", destType, "target", dest.Target)

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Destination worker stopping", "type", destType, "target", dest.Target)
			return
		case msg, ok := <-dest.msgChan:
			if !ok {
				s.log.Info("Destination channel closed, stopping worker", "type", destType, "target", dest.Target)
				return
			}
			if err := s.sendToDestination(ctx, dest, msg); err != nil {
				s.log.Error(err, "Failed to send audit log", "type", destType, "target", dest.Target)
			}
		}
	}
}

// Close closes the auditlog service
func (s *Service) Close(ctx context.Context) error {
	// Signal shutdown to prevent new sends
	s.closeOnce.Do(func() { close(s.done) })

	// Stop all destination workers via context cancellation
	for _, dest := range s.destinations {
		if dest.cancel != nil {
			dest.cancel()
		}
	}

	// Signal processAuditLog to stop
	if s.cancel != nil {
		s.cancel()
	}

	s.wg.Wait()

	// Final sync and close all file destinations
	for _, dest := range s.destinations {
		if dest.Type == DestinationFile && dest.File != nil {
			// Flush any remaining dirty data before closing
			s.mu.Lock()
			if dest.dirty {
				if err := dest.File.Sync(); err != nil {
					s.log.Error(err, "Failed to sync audit log file on close", "path", dest.Target)
				}
				dest.dirty = false
			}
			s.mu.Unlock()

			if err := dest.File.Close(); err != nil {
				s.log.Error(err, "Failed to close audit log file", "path", dest.Target)
			}
		}
	}

	s.log.Info("Stopped")

	return nil
}
