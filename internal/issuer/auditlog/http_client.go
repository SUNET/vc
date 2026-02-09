package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// SendWebHook sends audit log data to all configured destinations via worker queues
func (s *Service) SendWebHook(ctx context.Context, inData any) error {
	// If no destinations configured
	if len(s.destinations) == 0 {
		s.log.Debug("audit log event (no destinations configured)", "data", inData)
		return nil
	}

	jsonBytes, err := json.Marshal(inData)
	if err != nil {
		return err
	}

	// Send to all destination queues (non-blocking, shutdown-safe)
	for _, dest := range s.destinations {
		select {
		case <-s.done:
			s.log.Debug("service shutting down, dropping audit message", "target", dest.Target)
			return nil
		case dest.msgChan <- jsonBytes:
			// Message queued successfully
		default:
			s.log.Error(nil, "destination queue full, dropping message", "target", dest.Target)
		}
	}

	return nil
}

// sendToDestination sends audit log data to a specific destination
func (s *Service) sendToDestination(ctx context.Context, dest *Destination, jsonBytes []byte) error {
	// Add timestamp prefix to all destinations
	prefix := fmt.Sprintf("[AUDIT %s] ", time.Now().UTC().Format(time.RFC3339))
	messageWithPrefix := append([]byte(prefix), jsonBytes...)

	switch dest.Type {
	case DestinationConsole:
		log.Println(string(messageWithPrefix))
		return nil
	case DestinationWebhook:
		return s.sendWebhook(ctx, dest.Target, jsonBytes)
	case DestinationFile:
		return s.writeToFile(dest, messageWithPrefix)
	default:
		return errors.New("unknown destination type")
	}
}

// sendWebhook sends audit log data via HTTP POST
func (s *Service) sendWebhook(ctx context.Context, url string, jsonBytes []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		if err := Body.Close(); err != nil {
			log.Println("Error closing response body:", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	s.log.Debug("webhook delivered", "url", url)
	return nil
}

// writeToFile appends audit log data to a file.
// Sync behavior is controlled by the FileSyncInterval config option:
//   - FileSyncInterval=0:   fsync after every write (strict durability, lower throughput)
//   - FileSyncInterval>0:   periodic fsync at the configured interval (batched flushes, better throughput)
func (s *Service) writeToFile(dest *Destination, jsonBytes []byte) error {
	if dest.File == nil {
		return errors.New("file handle is nil")
	}

	// Use mutex to protect concurrent writes
	s.mu.Lock()
	defer s.mu.Unlock()

	// Write JSON with newline
	if _, err := dest.File.Write(append(jsonBytes, '\n')); err != nil {
		return err
	}

	// Sync strategy: immediate fsync when interval is 0 (strict durability);
	// otherwise mark dirty for periodic batched flush.
	if s.fileSyncInterval == 0 {
		if err := dest.File.Sync(); err != nil {
			return err
		}
	} else {
		dest.dirty = true
	}

	s.log.Debug("audit log written to file", "file", dest.Target)
	return nil
}

// periodicSync runs a background goroutine that flushes dirty file destinations
// at the configured SyncInterval. This amortises the cost of fsync across many
// writes while still bounding the window of data that could be lost on a crash.
func (s *Service) periodicSync(ctx context.Context, dest *Destination) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.fileSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			if dest.dirty && dest.File != nil {
				if err := dest.File.Sync(); err != nil {
					s.log.Error(err, "periodic sync failed", "file", dest.Target)
				}
				dest.dirty = false
			}
			s.mu.Unlock()
		}
	}
}
