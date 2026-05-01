package vcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
)

// Health checks the health of the Verifier service
func (s *VerifierClient) Health(ctx context.Context) (*apiv1_status.StatusReply, *http.Response, error) {
	s.log.Debug("Health (Verifier)")

	fullURL, err := url.JoinPath(s.baseURL, "/health")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp, err
	}

	jsonResp := &apiv1_status.StatusReply{}
	if err := json.Unmarshal(body, jsonResp); err != nil {
		return nil, resp, err
	}

	return jsonResp, resp, nil
}
