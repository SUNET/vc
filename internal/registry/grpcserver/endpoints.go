package grpcserver

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/internal/registry/apiv1"
)

// TokenStatusListAdd adds a new status entry to the Token Status List
func (s *Service) TokenStatusListAddStatus(ctx context.Context, req *apiv1_registry.TokenStatusListAddStatusRequest) (*apiv1_registry.TokenStatusListAddStatusReply, error) {
	if req.Status > 255 {
		return nil, fmt.Errorf("status value %d exceeds uint8 range", req.Status)
	}
	section, index, err := s.tokenStatusListIssuer.AddStatus(ctx, uint8(req.Status))
	if err != nil {
		return nil, err
	}

	// Same construction as the Status List Token's sub claim and as the
	// admin ownership check - see model.Registry.StatusListURL.
	statusListURI, err := s.cfg.Registry.StatusListURL(section)
	if err != nil {
		return nil, fmt.Errorf("failed to construct status list URI: %w", err)
	}

	reply := &apiv1_registry.TokenStatusListAddStatusReply{
		Section:       section,
		Index:         index,
		StatusListUri: statusListURI,
	}

	return reply, nil
}

// TokenStatusListUpdate updates an existing status entry in the Token Status List
//
// The caller must name the list it believes the entry lives in, and that
// name must be this registry's own URL for the section. (Section, index)
// are coordinates, not an identity: they address whatever list this
// registry exposes at those numbers right now. A mapping recorded against
// some other list - stale, migrated, or supplied by a caller that made it
// up - would otherwise land on an unrelated credential's entry and flip
// IT, leaving the intended credential valid. Both failures are silent,
// which is why this is checked here rather than trusted at the caller.
func (s *Service) TokenStatusListUpdateStatus(ctx context.Context, req *apiv1_registry.TokenStatusListUpdateStatusRequest) (*apiv1_registry.TokenStatusListUpdateStatusReply, error) {
	if req.Status > 255 {
		return nil, fmt.Errorf("status value %d exceeds uint8 range", req.Status)
	}

	// Same construction as TokenStatusListAddStatus hands back at
	// allocation, as the Status List Token's sub claim, and as the admin
	// ownership check - see model.Registry.StatusListURL. If those ever
	// diverge, every update starts failing loudly, which is the direction
	// this should fail in.
	canonical, err := s.cfg.Registry.StatusListURL(req.Section)
	if err != nil {
		return nil, fmt.Errorf("failed to construct status list URI for section %d: %w", req.Section, err)
	}
	// Empty is refused rather than waved through. "The caller did not say"
	// and "the caller named this list" are different claims, and only the
	// second one can be checked; accepting the first restores exactly the
	// unverified routing this field exists to close, for any caller that
	// simply omits it.
	if req.StatusListURI == "" {
		return nil, fmt.Errorf("status list URI is required to update entry %d/%d: the section and index alone do not identify which list the entry was allocated in", req.Section, req.Index)
	}
	if req.StatusListURI != canonical {
		return nil, fmt.Errorf("refusing to update entry %d/%d: the caller names list %q, but this registry serves %q at that section", req.Section, req.Index, req.StatusListURI, canonical)
	}

	err = s.tokenStatusListIssuer.UpdateStatus(ctx, req.Section, req.Index, uint8(req.Status))
	if err != nil {
		return nil, err
	}

	return &apiv1_registry.TokenStatusListUpdateStatusReply{}, nil
}

// SaveCredentialSubject saves credential subject info linked to a Token Status List entry
func (s *Service) SaveCredentialSubject(ctx context.Context, req *apiv1_registry.SaveCredentialSubjectRequest) (*apiv1_registry.SaveCredentialSubjectReply, error) {
	err := s.apiv1.SaveCredentialSubject(ctx, &apiv1.SaveCredentialSubjectRequest{
		Identifier:    req.Identifier,
		Section:       req.Section,
		Index:         req.Index,
		StatusListURI: req.StatusListURI,
	})
	if err != nil {
		return nil, err
	}

	return &apiv1_registry.SaveCredentialSubjectReply{}, nil
}

// Status returns the readiness status of the registry service and its
// dependencies.
func (s *Service) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	return s.apiv1.Status(ctx, req)
}
