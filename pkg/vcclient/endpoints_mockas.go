package vcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Health checks the health of the MockAS service
func (s *MockASClient) Health(ctx context.Context) (map[string]any, *http.Response, error) {
	s.log.Debug("Health (MockAS)")

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

	var jsonResp map[string]any
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, resp, err
	}

	return jsonResp, resp, nil
}

// MockNextRequest is the request for MockNext
type MockNextRequest map[string]any

// MockNext sends a mock action request
func (s *MockASClient) MockNext(ctx context.Context, req MockNextRequest) (map[string]any, *http.Response, error) {
	s.log.Debug("MockNext (MockAS)")

	fullURL, err := url.JoinPath(s.baseURL, "/api/v1/mock/next")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}

	reqBodyJSON, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBuffer(reqBodyJSON))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.client.httpClient.Do(httpReq)
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

	var jsonResp map[string]any
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, resp, err
	}

	return jsonResp, resp, nil
}
