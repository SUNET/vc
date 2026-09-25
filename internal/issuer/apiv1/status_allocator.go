package apiv1

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/statusserviceclient"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
)

// statusAllocation is a source-agnostic status-list entry allocated for one
// credential about to be issued, per draft-ietf-oauth-status-list.
//
// Section only means something for a registryStatusAllocator: it is a
// concept internal to vc's own built-in Token Status List (which shards its
// list into fixed-size "sections"), and has no equivalent when an external
// service such as siros-status-service is providing the list instead -
// externalStatusAllocator always leaves it 0.
type statusAllocation struct {
	Section int64
	Index   int64
	URI     string
}

// statusAllocator allocates and updates status-list entries for issued
// credentials, regardless of whether they come from vc's own built-in Token
// Status List (via the registry gRPC service) or an external
// draft-ietf-oauth-status-list-21 service such as siros-status-service.
// Client.statusAllocator picks one at startup based on configuration - see
// initStatusAllocator - so every issuance path (MakeSDJWT, MakeJWP,
// MakeVC20) can go through this interface without caring which backend is
// live.
type statusAllocator interface {
	// Allocate reserves a fresh, VALID status-list entry for a credential
	// about to be issued.
	Allocate(ctx context.Context) (*statusAllocation, error)
	// Invalidate marks an allocated entry INVALID, best-effort, because the
	// credential it was reserved for was never actually issued (a later
	// step in the same request failed). Errors are logged, not returned:
	// every existing caller of the registry-only predecessor of this
	// (handlers_bbs.go's invalidateStatusEntry) already treated this as
	// best-effort - the issuance has already failed, and a service that
	// was unreachable for this call was reachable moments ago for the
	// allocation, so there is nothing better to do than log it.
	Invalidate(ctx context.Context, alloc *statusAllocation)
}

// registryStatusAllocator adapts vc's own built-in Token Status List (the
// registry gRPC service) to statusAllocator. This is the pre-existing
// behaviour, unchanged.
type registryStatusAllocator struct {
	client apiv1_registry.RegistryServiceClient
	log    *logger.Log
}

func (a *registryStatusAllocator) Allocate(ctx context.Context) (*statusAllocation, error) {
	reply, err := a.client.TokenStatusListAddStatus(ctx, &apiv1_registry.TokenStatusListAddStatusRequest{
		Status: 0, // VALID status for new credential
	})
	if err != nil {
		return nil, err
	}
	return &statusAllocation{Section: reply.GetSection(), Index: reply.GetIndex(), URI: reply.GetStatusListUri()}, nil
}

func (a *registryStatusAllocator) Invalidate(ctx context.Context, alloc *statusAllocation) {
	if _, err := a.client.TokenStatusListUpdateStatus(ctx, &apiv1_registry.TokenStatusListUpdateStatusRequest{
		Section: alloc.Section,
		Index:   alloc.Index,
		Status:  uint32(tokenstatuslist.StatusInvalid),
	}); err != nil {
		a.log.Error(err, "could not invalidate registry status entry of a failed issuance",
			"section", alloc.Section, "index", alloc.Index)
	}
}

// externalStatusAllocator adapts a pool-based statusserviceclient.Client
// (talking to an external draft-ietf-oauth-status-list-21 service) to
// statusAllocator.
type externalStatusAllocator struct {
	client *statusserviceclient.Client
	log    *logger.Log
}

func (a *externalStatusAllocator) Allocate(ctx context.Context) (*statusAllocation, error) {
	entry, err := a.client.Take(ctx)
	if err != nil {
		return nil, err
	}
	return &statusAllocation{Index: int64(entry.Index), URI: entry.ListURL}, nil
}

func (a *externalStatusAllocator) Invalidate(ctx context.Context, alloc *statusAllocation) {
	listID, err := statusserviceclient.ListIDFromURL(alloc.URI)
	if err != nil {
		a.log.Error(err, "could not determine list ID to invalidate a failed issuance's status entry", "uri", alloc.URI)
		return
	}
	if err := a.client.SetStatus(ctx, listID, uint64(alloc.Index), statusserviceclient.StatusInvalid); err != nil {
		a.log.Error(err, "could not invalidate external status service entry of a failed issuance",
			"list_id", listID, "index", alloc.Index)
	}
}

// allocateOrDegrade is the single place every issuance path (MakeSDJWT,
// MakeJWP, MakeVC20) goes through to get a status-list entry.
//
//   - No allocator configured at all (neither the registry nor the external
//     status service): returns (nil, err). Each issuance path decides for
//     itself, as before, whether that is fatal (SD-JWT and BBS always
//     required one; VC20 has always treated it as best-effort by checking
//     for a nil registry client before ever calling this) - this function
//     does not change that, it only supplies the error to react to.
//   - The active backend's Allocate fails, and that backend is vc's own
//     registry: returns (nil, err) unconditionally. This is a no-op
//     preservation of this repository's pre-existing behaviour - nothing
//     about how the registry-only configuration behaves changes.
//   - The active backend's Allocate fails, and that backend is the external
//     status service: consults Issuer.StatusService.DegradedMode. "fail"
//     (or an explicitly unrecognised value) returns (nil, err), same as the
//     registry case. "proceed" (the default) instead logs the failure and
//     returns (nil, nil) - the caller should issue the credential without a
//     status claim.
//
// This applies DegradedMode uniformly across all three issuance paths once
// the external status service is configured, which is a deliberate,
// documented behaviour change from VC20's own historical registry-specific
// best-effort default: that default is preserved exactly when the registry
// is the active backend (a true no-op), and is superseded by the explicit
// degraded_mode setting once the external service takes over, so all three
// credential formats behave consistently under the new feature.
func (c *Client) allocateOrDegrade(ctx context.Context) (*statusAllocation, error) {
	if c.statusAllocator == nil {
		return nil, fmt.Errorf("no status allocator configured (neither issuer.registry_client nor issuer.status_service)")
	}

	alloc, err := c.statusAllocator.Allocate(ctx)
	if err == nil {
		return alloc, nil
	}

	if c.statusServiceClient != nil && c.statusServiceDegradedModeProceeds() {
		c.log.Error(err, "external status service allocation failed; issuing credential without a status claim per degraded_mode=proceed")
		return nil, nil
	}
	return nil, err
}

// allocateOptionalStatus allocates a status entry for an issuance path that
// has never REQUIRED one (mdoc, VC 2.0), without throwing away the external
// backend's degraded-mode contract.
//
// Those paths were best-effort against the registry long before an external
// service existed, and that stays: no allocator configured, or a registry
// allocation that fails, issues the credential without revocation support
// and logs. But `degraded_mode: fail` is an operator saying "reject the
// issuance rather than issue something unrevocable", and honouring it only
// in the SD-JWT/BBS paths would make the setting quietly format-dependent.
// So when the external backend is the one configured, this defers to
// allocateOrDegrade, which fails or degrades as configured.
//
// Returns (nil, nil) when there is nothing to allocate or the failure is one
// the caller should absorb; a non-nil error means the issuance must stop.
func (c *Client) allocateOptionalStatus(ctx context.Context, format string) (*statusAllocation, error) {
	if c.statusAllocator == nil {
		return nil, nil
	}

	if c.statusServiceClient != nil {
		// External backend: degraded_mode decides, exactly as it does for
		// the formats that always allocate.
		return c.allocateOrDegrade(ctx)
	}

	alloc, err := c.statusAllocator.Allocate(ctx)
	if err != nil {
		c.log.Info("failed to allocate status list entry, issuing without revocation support",
			"format", format, "error", err)
		return nil, nil
	}
	return alloc, nil
}

// statusServiceDegradedModeProceeds reports whether a failed external
// allocation should degrade to "issue without a status claim" (true, the
// default) rather than fail the request (false, degraded_mode: "fail").
func (c *Client) statusServiceDegradedModeProceeds() bool {
	scfg := c.cfg.Issuer.StatusService
	return scfg == nil || scfg.DegradedMode == "" || scfg.DegradedMode == "proceed"
}
