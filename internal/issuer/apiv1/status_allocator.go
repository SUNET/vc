package apiv1

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/helpers"
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
	// Backend names which status-list implementation issued this entry.
	//
	// It is recorded rather than inferred later. At revocation time all
	// that survives is the stored entry, and the URI alone does not say
	// which backend owns it: a registry list and an external service's list
	// are both just ".../statuslists/<something>", and an issuer can have
	// been reconfigured between issuance and revocation. Guessing wrong
	// means writing a status into the wrong list - flipping an unrelated
	// credential while leaving the intended one valid. The allocator knows
	// the answer for certain at the only moment it is free, so it says so.
	Backend string
}

// The status-list backends an entry can come from. Aliases of the shared
// names in pkg/tokenstatuslist, which is where they are defined so that the
// issuer, the apigw and the database layer cannot disagree about spelling.
const (
	StatusBackendRegistry      = tokenstatuslist.BackendRegistry
	StatusBackendStatusService = tokenstatuslist.BackendStatusService
)

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
	return &statusAllocation{
		Section: reply.GetSection(),
		Index:   reply.GetIndex(),
		URI:     reply.GetStatusListUri(),
		Backend: StatusBackendRegistry,
	}, nil
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
	// Entry.Index is uint64 and statusAllocation.Index is int64, so a value
	// above MaxInt64 would wrap to a negative index. Nothing downstream
	// checks the sign - it would be written into a credential's status
	// claim and into the entry record - so refuse it here rather than
	// issue a credential pointing at index -1.
	if entry.Index > math.MaxInt64 {
		return nil, fmt.Errorf("status service returned index %d, which does not fit a signed 64-bit index", entry.Index)
	}
	return &statusAllocation{
		Index:   int64(entry.Index),
		URI:     entry.ListURL,
		Backend: StatusBackendStatusService,
	}, nil
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

// releaseUnlessIssued hands an allocated status entry back when issuance
// did not finish. Called from a defer immediately after allocation, with
// issued set to true only on the path that actually returns a credential:
//
//	alloc, err := c.allocateOrDegrade(ctx)
//	...
//	issued := false
//	defer c.releaseUnlessIssued(ctx, alloc, &issued)
//	...
//	issued = true
//	return reply, nil
//
// A defer rather than a call at each error site: the sites are what get
// missed. Three handlers had allocation followed by four or five ways to
// fail and no invalidation on any of them, and every later failure path
// added is one more chance to forget.
//
// An entry left VALID with nothing referencing it is not exploitable - no
// credential carries that index - but it is a wrong answer sitting in a
// list whose whole job is answering that question, and it accumulates one
// per failed request.
//
// Best-effort by construction: the issuance has already failed, and a
// backend that cannot be reached to invalidate could not have been reached
// to allocate either. Logged inside Invalidate, never returned in place of
// the real error.
//
// The context is detached from the caller's. A cancelled or timed-out
// request is one of the ways issuance fails, and inheriting that
// cancellation would guarantee the cleanup fails exactly when it is needed.
func (c *Client) releaseUnlessIssued(ctx context.Context, alloc *statusAllocation, issued *bool) {
	if alloc == nil || issued == nil || *issued || c.statusAllocator == nil {
		return
	}
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusReleaseTimeout)
	defer cancel()
	c.statusAllocator.Invalidate(releaseCtx, alloc)
}

// statusReleaseTimeout bounds the best-effort release above. Long enough
// for one round trip to a status backend, short enough that a hung backend
// does not hold the failing request open.
const statusReleaseTimeout = 5 * time.Second

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
		// An allocation without a list URI is unusable: the credential
		// would carry an index into a list nothing identifies, so no
		// verifier could resolve it and the slot would be consumed for
		// nothing. Hand the entry back and treat it as an allocation
		// failure, so degraded_mode decides what happens next exactly as
		// it does for any other failure of the backend.
		//
		// This is checked here rather than in each issuance path because
		// every format needs the URI - SD-JWT and JWP put it in the
		// credential's status claim, mdoc in the MSO, VC 2.0 in
		// credentialStatus - and a check per path is a check that will be
		// missing from the next path somebody adds.
		switch {
		case alloc == nil:
			err = errors.New("status allocator returned no entry and no error")
		case alloc.URI == "":
			err = fmt.Errorf("status allocation returned no status list URI (section %d, index %d)", alloc.Section, alloc.Index)
			c.statusAllocator.Invalidate(ctx, alloc)
		default:
			return alloc, nil
		}
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
	// Same reasoning as allocateOrDegrade: an entry with no list URI is
	// not usable by any format. This path is best-effort, so hand the slot
	// back and issue without revocation support rather than failing.
	if alloc == nil || alloc.URI == "" {
		if alloc != nil {
			c.statusAllocator.Invalidate(ctx, alloc)
		}
		c.log.Info("status allocation returned no status list URI, issuing without revocation support",
			"format", format)
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

// SetCredentialStatusRequest asks for one already-issued credential's
// status-list entry to be set to a new value.
type SetCredentialStatusRequest struct {
	// Backend names the status-list implementation that issued the entry,
	// as recorded at issuance time. See statusAllocation.Backend for why
	// this is carried rather than inferred from the URI.
	Backend string `json:"backend" validate:"required"`
	// StatusListURI is the list the entry lives in. Required for both
	// backends: it is how the status service addresses a list, and for the
	// registry it is what lets a caller confirm the entry it is acting on
	// is the one it looked up.
	StatusListURI string `json:"status_list_uri" validate:"required,url"`
	// Section is meaningful only for the registry backend.
	Section int64 `json:"section" validate:"gte=0"`
	Index   int64 `json:"index" validate:"gte=0"`
	// Status is the draft-ietf-oauth-status-list value to write: 0 VALID,
	// 1 INVALID, 2 SUSPENDED.
	//
	// Only those three are accepted. The wire format has room for 0-255,
	// but this issuer has no way to express an unassigned value to the
	// external backend - its API speaks the names - so accepting one would
	// mean either inventing a name or writing something the operator did
	// not ask for.
	Status uint8 `json:"status" validate:"oneof=0 1 2"`
}

// SetCredentialStatus writes a new status for an already-issued credential's
// entry, routing to whichever backend allocated it.
//
// This is the revocation counterpart to allocation, and it lives here for
// the same reason allocation does: the issuer is the one component
// configured with both backends, so routing between them happens once, in
// the place that already knows how to reach each. Callers (the apigw revoke
// API) need to know nothing about status lists beyond what they recorded at
// issuance.
//
// It refuses rather than guesses when the named backend is not configured.
// Silently falling back to the other one would write the status into a
// different list, which flips an unrelated credential and leaves the
// intended one valid.
func (c *Client) SetCredentialStatus(ctx context.Context, req *SetCredentialStatusRequest) error {
	ctx, span := c.tracer.Start(ctx, "apiv1:SetCredentialStatus")
	defer span.End()

	if req == nil {
		return errors.New("request is required")
	}
	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		return err
	}

	// Checked before the switch so that an unknown name is refused by the
	// same rule everywhere, rather than by a validator tag here and a
	// default branch there that could drift apart.
	if !tokenstatuslist.ValidBackend(req.Backend) {
		return fmt.Errorf("unknown status list backend %q", req.Backend)
	}

	switch req.Backend {
	case StatusBackendRegistry:
		if c.registryClient == nil {
			return fmt.Errorf("cannot set the status of entry %d/%d: this issuer has no registry client configured, and the entry was issued by the registry backend", req.Section, req.Index)
		}
		if _, err := c.registryClient.TokenStatusListUpdateStatus(ctx, &apiv1_registry.TokenStatusListUpdateStatusRequest{
			Section: req.Section,
			Index:   req.Index,
			Status:  uint32(req.Status),
		}); err != nil {
			return fmt.Errorf("registry status update failed for %d/%d: %w", req.Section, req.Index, err)
		}
		return nil

	case StatusBackendStatusService:
		if c.statusServiceClient == nil {
			return fmt.Errorf("cannot set the status of entry %d in %q: this issuer has no status service configured, and the entry was issued by an external status service", req.Index, req.StatusListURI)
		}
		listID, err := statusserviceclient.ListIDFromURL(req.StatusListURI)
		if err != nil {
			return fmt.Errorf("cannot determine the list ID of %q: %w", req.StatusListURI, err)
		}

		status, err := externalStatusName(req.Status)
		if err != nil {
			return err
		}
		if err := c.statusServiceClient.SetStatus(ctx, listID, uint64(req.Index), status); err != nil {
			return fmt.Errorf("status service update failed for index %d in list %q: %w", req.Index, listID, err)
		}
		return nil

	default:
		// Validation above already rejects this; the branch exists so that
		// adding a backend without adding a case here fails loudly rather
		// than silently doing nothing.
		return fmt.Errorf("unknown status list backend %q", req.Backend)
	}
}

// externalStatusName maps a draft-ietf-oauth-status-list numeric status to
// the name the external status service's API uses.
//
// The conversion has to be a lookup, not a cast. statusserviceclient.Status
// is a STRING type whose values are "VALID"/"INVALID"/"SUSPENDED", so
// statusserviceclient.Status(uint8(1)) does not produce "INVALID" - Go
// converts the integer to the UTF-8 encoding of that code point, yielding
// "\x01", which the service receives as a status it has never heard of.
// Every revoke, suspend and reinstate against an external backend would
// have been silently meaningless.
//
// An unrecognised value is an error rather than a default, because there is
// no safe guess: defaulting to INVALID revokes a credential the caller did
// not ask to revoke, and defaulting to VALID un-revokes one.
func externalStatusName(status uint8) (statusserviceclient.Status, error) {
	switch status {
	case tokenstatuslist.StatusValid:
		return statusserviceclient.StatusValid, nil
	case tokenstatuslist.StatusInvalid:
		return statusserviceclient.StatusInvalid, nil
	case tokenstatuslist.StatusSuspended:
		return statusserviceclient.StatusSuspended, nil
	default:
		return "", fmt.Errorf("status %d has no name in the external status service API (only 0 VALID, 1 INVALID and 2 SUSPENDED do)", status)
	}
}
