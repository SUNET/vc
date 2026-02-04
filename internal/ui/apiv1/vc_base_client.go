package apiv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

type VCBaseClient struct {
	serviceName string
	baseUrl     string
	logger      *logger.Log
	httpClient  *http.Client
	tp          *trace.Tracer
}

func NewClient(serviceName string, baseUrl string, tracer *trace.Tracer, logger *logger.Log) *VCBaseClient {
	client := &VCBaseClient{
		serviceName: serviceName,
		baseUrl:     baseUrl,
		httpClient: &http.Client{
			//TODO(mk): set timeout in config
			Timeout: 10 * time.Second,
		},
		logger: logger,
		tp:     tracer,
	}
	return client
}

// TODO(mk): DEPRECATED USE GENERIC POST FUNC
func (c *VCBaseClient) DoPostJSON(endpoint string, reqBody any) (*map[string]any, error) {
	url := c.url(endpoint)

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer c.closeBody(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonResp map[string]any
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, err
	}

	return &jsonResp, nil
}

func DoPostJSONGeneric[T any](c *VCBaseClient, endpoint string, reqBody any) (*T, error) {
	url := c.url(endpoint)

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {

		return nil, err
	}
	defer c.closeBody(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	//TODO(mk): also return resp.StatusCode in all returns below

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonResp T
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, err
	}

	return &jsonResp, nil
}

func (c *VCBaseClient) DoDelete(endpoint string, reqBody any) error {
	url := c.url(endpoint)

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("DELETE", url, bytes.NewBuffer(reqBodyJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer c.closeBody(resp)

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func (c *VCBaseClient) DoGetJSON(endpoint string) (*map[string]any, error) {
	url := c.url(endpoint)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer c.closeBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonResp map[string]any
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, err
	}

	return &jsonResp, nil
}

func (c *VCBaseClient) url(path string) string {
	baseURL, err := url.Parse(c.baseUrl)
	if err != nil {
		c.logger.Error(err, "failed to parse base URL")
		return c.baseUrl + path // fallback to old behavior
	}
	fullURL, err := url.JoinPath(baseURL.String(), path)
	if err != nil {
		c.logger.Error(err, "failed to join URL path")
		return c.baseUrl + path // fallback to old behavior
	}
	return fullURL
}

func (c *VCBaseClient) closeBody(resp *http.Response) {
	func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			c.logger.Error(err, "could not close response body")
		}
	}(resp.Body)
}
