package ts11client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Config configures a MultiRegistryClient.
type Config struct {
	// Registries are queried concurrently for every resolution - the
	// first to answer wins (happy-eyeballs style), so one slow or
	// unreachable registry never blocks resolution as long as another
	// configured registry has the answer.
	Registries []RegistryConfig
	// Local, if set, is checked first (synchronously, no network) and
	// always wins over any registry - it exists so an existing
	// vendored-local-file configuration keeps working unchanged when
	// registries are introduced alongside it.
	Local *LocalSource
	// RefreshInterval controls how long a registry's discovery index (and
	// derived doctype index) is trusted before being re-fetched. Zero
	// means fetch once and cache forever (matches "always serve from
	// cache" as the default - there is no time-based invalidation unless
	// this is set).
	RefreshInterval time.Duration
	// HTTPClient is used for all registry requests. Defaults to
	// http.DefaultClient if nil.
	HTTPClient *http.Client
}

// MultiRegistryClient implements Client over a LocalSource (checked
// first, always wins) plus zero or more TS11 registries (queried
// concurrently, first hit wins).
type MultiRegistryClient struct {
	local      *LocalSource
	registries []*registryHandle
}

// New builds a MultiRegistryClient from cfg. At least one of cfg.Local or
// cfg.Registries must be set.
func New(cfg Config) (*MultiRegistryClient, error) {
	if cfg.Local == nil && len(cfg.Registries) == 0 {
		return nil, fmt.Errorf("ts11client: at least one of Local or Registries must be configured")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	handles := make([]*registryHandle, 0, len(cfg.Registries))
	for _, rc := range cfg.Registries {
		if rc.BaseURL == "" {
			return nil, fmt.Errorf("ts11client: registry BaseURL cannot be empty")
		}
		handles = append(handles, newRegistryHandle(rc, httpClient, cfg.RefreshInterval))
	}

	return &MultiRegistryClient{local: cfg.Local, registries: handles}, nil
}

var _ Client = (*MultiRegistryClient)(nil)

// ResolveVCT implements Client.
func (c *MultiRegistryClient) ResolveVCT(ctx context.Context, vct string) (*Resolved, error) {
	if res, err := c.local.ResolveVCT(ctx, vct); err == nil {
		return res, nil
	}
	return race(ctx, c.registries, func(ctx context.Context, h *registryHandle) (*Resolved, error) {
		return h.resolveVCT(ctx, vct)
	})
}

// ResolveDoctype implements Client.
func (c *MultiRegistryClient) ResolveDoctype(ctx context.Context, doctype string) (*Resolved, error) {
	if res, err := c.local.ResolveDoctype(ctx, doctype); err == nil {
		return res, nil
	}
	return race(ctx, c.registries, func(ctx context.Context, h *registryHandle) (*Resolved, error) {
		return h.resolveDoctype(ctx, doctype)
	})
}

// race queries every registry in handles concurrently via resolve,
// returning the first successful result (happy-eyeballs style) and
// canceling the rest. If every registry fails (including "not found"),
// returns an error wrapping ErrNotFound summarizing all of them.
func race(ctx context.Context, handles []*registryHandle, resolve func(context.Context, *registryHandle) (*Resolved, error)) (*Resolved, error) {
	if len(handles) == 0 {
		return nil, fmt.Errorf("%w: no registries configured", ErrNotFound)
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		res *Resolved
		err error
	}
	results := make(chan result, len(handles))
	for _, h := range handles {
		h := h
		go func() {
			res, err := resolve(raceCtx, h)
			results <- result{res: res, err: err}
		}()
	}

	var errs []error
	for range handles {
		r := <-results
		if r.err == nil {
			cancel() // stop the other in-flight registry queries
			return r.res, nil
		}
		errs = append(errs, r.err)
	}
	return nil, fmt.Errorf("%w: %w", ErrNotFound, errors.Join(errs...))
}
