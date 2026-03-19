// Package registry provides trust registry management.
// This file contains shared HTTP utility functions.
package registry

import (
	"fmt"
	"io"
	"sync"
)

// DefaultMaxResponseBodyBytes is the default maximum HTTP response body size (10 MB).
const DefaultMaxResponseBodyBytes = 10 * 1024 * 1024

var (
	maxResponseBodyBytes = DefaultMaxResponseBodyBytes
	maxResponseMu        sync.RWMutex
)

// SetMaxResponseBodyBytes configures the global maximum HTTP response body size.
// This should be called once at startup before any HTTP fetches occur.
func SetMaxResponseBodyBytes(n int) {
	if n <= 0 {
		n = DefaultMaxResponseBodyBytes
	}
	maxResponseMu.Lock()
	maxResponseBodyBytes = n
	maxResponseMu.Unlock()
}

// GetMaxResponseBodyBytes returns the current maximum HTTP response body size.
func GetMaxResponseBodyBytes() int {
	maxResponseMu.RLock()
	defer maxResponseMu.RUnlock()
	return maxResponseBodyBytes
}

// LimitedReader wraps an io.Reader with the configured body size limit.
func LimitedReader(r io.Reader) io.Reader {
	limit := GetMaxResponseBodyBytes()
	return io.LimitReader(r, int64(limit)+1)
}

// ReadLimitedBody reads up to the configured maximum from r.
// Returns an error if the body exceeds the limit.
func ReadLimitedBody(r io.Reader) ([]byte, error) {
	limit := GetMaxResponseBodyBytes()
	limited := io.LimitReader(r, int64(limit)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("response body exceeds maximum size of %d bytes", limit)
	}
	return data, nil
}
