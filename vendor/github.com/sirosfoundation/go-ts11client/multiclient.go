package ts11client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// LogicalRegistry is one independent TS11 registry, optionally served by
// more than one mirror endpoint holding equivalent content. Mirrors are
// queried concurrently and race - happy-eyeballs, first hit wins - since
// they're expected to hold the same data. Distinct LogicalRegistry entries
// are NOT raced against each other: they may hold different, non-
// overlapping credentials (e.g. one org's own registry plus a federation
// partner's), so racing them would be meaningless when only one of them
// actually has a given key. See Config.Registries for how they combine.
type LogicalRegistry struct {
	// Mirrors is the set of endpoints serving this logical registry's
	// content. At least one is required.
	Mirrors []RegistryConfig
}

// Config configures a MultiRegistryClient.
type Config struct {
	// Registries is an ordered list of logical (independent) registries.
	// A later entry overrides an earlier one for the same key - the same
	// convention a deployment-local registry uses to extend or override a
	// shared upstream one - so resolution tries registries from the end
	// of the list backwards, stopping at the first hit. Racing
	// (happy-eyeballs, first-hit-wins) only ever happens within a single
	// LogicalRegistry's Mirrors, never across distinct entries in this
	// list - see LogicalRegistry's doc comment for why.
	Registries []LogicalRegistry
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

// logicalRegistryHandle is the resolved (registryHandle-backed) form of a
// LogicalRegistry.
type logicalRegistryHandle struct {
	mirrors []*registryHandle
}

// MultiRegistryClient implements Client over a LocalSource (checked
// first, always wins) plus zero or more logical TS11 registries.
type MultiRegistryClient struct {
	local      *LocalSource
	registries []logicalRegistryHandle
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

	registries := make([]logicalRegistryHandle, 0, len(cfg.Registries))
	for _, lr := range cfg.Registries {
		if len(lr.Mirrors) == 0 {
			return nil, fmt.Errorf("ts11client: a logical registry must have at least one mirror")
		}
		mirrors := make([]*registryHandle, 0, len(lr.Mirrors))
		for _, rc := range lr.Mirrors {
			if rc.BaseURL == "" {
				return nil, fmt.Errorf("ts11client: registry BaseURL cannot be empty")
			}
			mirrors = append(mirrors, newRegistryHandle(rc, httpClient, cfg.RefreshInterval))
		}
		registries = append(registries, logicalRegistryHandle{mirrors: mirrors})
	}

	return &MultiRegistryClient{local: cfg.Local, registries: registries}, nil
}

var _ Client = (*MultiRegistryClient)(nil)

// ResolveVCT implements Client.
func (c *MultiRegistryClient) ResolveVCT(ctx context.Context, vct string) (*Resolved, error) {
	if res, err := c.local.ResolveVCT(ctx, vct); err == nil {
		return res, nil
	}
	return resolveAcrossRegistries(ctx, c.registries, func(ctx context.Context, h *registryHandle) (*Resolved, error) {
		return h.resolveVCT(ctx, vct)
	})
}

// ResolveDoctype implements Client.
func (c *MultiRegistryClient) ResolveDoctype(ctx context.Context, doctype string) (*Resolved, error) {
	if res, err := c.local.ResolveDoctype(ctx, doctype); err == nil {
		return res, nil
	}
	return resolveAcrossRegistries(ctx, c.registries, func(ctx context.Context, h *registryHandle) (*Resolved, error) {
		return h.resolveDoctype(ctx, doctype)
	})
}

// resolveAcrossRegistries tries logical registries in reverse list order
// (last, i.e. highest override priority, first), stopping at the first
// hit; within each logical registry, its mirrors are raced concurrently
// via race(). If every logical registry misses, returns an error wrapping
// ErrNotFound summarizing all of them.
func resolveAcrossRegistries(ctx context.Context, registries []logicalRegistryHandle, resolve func(context.Context, *registryHandle) (*Resolved, error)) (*Resolved, error) {
	if len(registries) == 0 {
		return nil, fmt.Errorf("%w: no registries configured", ErrNotFound)
	}

	var errs []error
	for i := len(registries) - 1; i >= 0; i-- {
		res, err := race(ctx, registries[i].mirrors, resolve)
		if err == nil {
			return res, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("%w: %w", ErrNotFound, errors.Join(errs...))
}

// race queries every mirror in handles concurrently via resolve,
// returning the first successful result (happy-eyeballs style) and
// canceling the rest. Intended for handles that are mirrors of the same
// logical registry (equivalent content) - see LogicalRegistry. If every
// mirror fails (including "not found"), returns an error wrapping
// ErrNotFound summarizing all of them.
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
