package apiv1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
)

func (c *Client) uploader(ctx context.Context, upload *uploadMock) (*http.Response, error) {
	c.log.Debug("uploading bootstrap mock")
	c.log.Debug("upload", "upload", upload)
	resp, err := c.call(
		ctx,
		http.MethodPost,
		"/api/v1/upload",
		upload,
		nil,
	)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// NewRequest make a new request
func (c *Client) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(c.cfg.MockAS.DatastoreURL)
	if err != nil {
		return nil, err
	}
	url := u.ResolveReference(rel)

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err = json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url.String(), buf)
	if err != nil {
		return nil, err
	}
	c.log.Debug("newrequest", "method", method, "url", url.String())

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

// Do does the new request
func (c *Client) do(ctx context.Context, req *http.Request, value any) (*http.Response, error) {
	_, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Validate request URL scheme to prevent SSRF
	if req.URL == nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
		return nil, fmt.Errorf("invalid URL scheme: %v", req.URL)
	}
	resp, err := c.httpClient.Do(req) //#nosec G704 -- URL from trusted config (DatastoreURL)
	if err != nil {
		c.log.Debug("httpClient do", "error", err)
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		buf := &bytes.Buffer{}
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			c.log.Debug("ReadForm", "error", err)
			return nil, err
		}
		caError := &helpers.Error{}
		if err := json.Unmarshal(buf.Bytes(), caError); err != nil {
			c.log.Debug("json unmarshal", "error", err)
			return nil, err
		}
		return nil, caError
	}

	c.log.Debug("do", "body", resp.Body, "status", resp.StatusCode)

	return resp, nil
}

func checkResponse(r *http.Response) error {
	switch r.StatusCode {
	case 200, 201, 202, 204, 304:
		return nil
	case 400:
		return errors.New("bad request")
	case 401:
		return errors.New("unauthorized")
	case 403:
		return errors.New("forbidden")
	case 404:
		return errors.New("not found")
	case 409:
		return errors.New("document already exists")
	case 500:
		return errors.New("internal server error")
	case 503:
		return errors.New("service unavailable")
	}
	return fmt.Errorf("unexpected status code: %d", r.StatusCode)
}

func (c *Client) call(ctx context.Context, method, path string, body, reply any) (*http.Response, error) {
	request, err := c.newRequest(
		ctx,
		method,
		path,
		body,
	)
	if err != nil {
		c.log.Error(err, "call failed")
		return nil, err
	}

	resp, err := c.do(ctx, request, reply)
	if err != nil {
		c.log.Error(err, "do failed")
		return resp, err
	}

	return resp, nil
}
