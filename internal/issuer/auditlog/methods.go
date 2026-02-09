package auditlog

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// AddAuditLog adds an audit log entry to auditLogChan channel.
func (s *Service) AddAuditLog(ctx context.Context, eventType string, message any) {
	s.auditLogChan <- &AuditLog{
		EventType: eventType,
		Date:      time.Now().Format(time.RFC3339),
		ID:        uuid.NewString(),
		Message:   message,
	}
}

// processAuditLog processes the audit log entries from the channel and sends them to the webhook
func (s *Service) processAuditLog(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Audit log service stopped")
			return
		case auditLog := <-s.auditLogChan:
			s.log.Info("Processing audit log", "event", auditLog.EventType, "id", auditLog.ID)
			err := s.SendWebHook(ctx, auditLog)
			if err != nil {
				s.log.Error(err, "Error sending webhook")
			}
		}
	}
}
