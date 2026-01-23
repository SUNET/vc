package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"
)

// SendWebHook calls the audit log notification endpoint (hook)
func (s *Service) SendWebHook(ctx context.Context, inData any) error {
	jsonBytes, err := json.Marshal(inData)
	if err != nil {
		return err
	}

	as, ok := s.cfg.AuthenticSources[s.cfg.Issuer.Identifier]
	if !ok {
		return errors.New("authentic source not found")
	}

	// Prepare the webhook request
	req, err := http.NewRequest("POST", as.NotificationEndpoint.URL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the webhook request
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

	// Determine the status based on the response code
	status := "failed"
	if resp.StatusCode == http.StatusOK {
		status = "delivered"
	}

	s.log.Debug("webhook status", "status", status)

	if status == "failed" {
		return errors.New(status)
	}

	return nil
}
