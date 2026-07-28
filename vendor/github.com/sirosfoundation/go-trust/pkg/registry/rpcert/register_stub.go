package rpcert

import (
	"context"
	"fmt"
)

// StubRegisterClient is a placeholder implementation of NationalRegisterClient.
// It returns an error for all lookups since the National Register API is not yet
// implemented. Replace with a real implementation when the TS5/TS6 API
// specification is finalized.
type StubRegisterClient struct {
	baseURL string
}

// NewStubRegisterClient creates a stub register client.
func NewStubRegisterClient(baseURL string) *StubRegisterClient {
	return &StubRegisterClient{baseURL: baseURL}
}

// LookupRP always returns an error because the National Register API is not
// yet implemented. Callers should handle the error as "register unavailable".
func (c *StubRegisterClient) LookupRP(_ context.Context, rpIdentifier string) (*RPEntitlements, error) {
	return nil, fmt.Errorf("national register lookup not implemented (base_url=%s, rp=%s)", c.baseURL, rpIdentifier)
}

// Healthy returns true if a base URL is configured, false otherwise.
// A non-empty URL indicates the client was configured with an endpoint,
// even though the implementation is a stub.
func (c *StubRegisterClient) Healthy() bool {
	return c.baseURL != ""
}
