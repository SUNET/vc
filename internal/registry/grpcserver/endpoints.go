package grpcserver

import (
	"context"
	"fmt"
	"net/url"

	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
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

	baseURL, err := url.Parse(s.cfg.Registry.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("invalid registry public URL: %w", err)
	}
	baseURL.Path, err = url.JoinPath(baseURL.Path, "statuslists", fmt.Sprintf("%d", section))
	if err != nil {
		return nil, fmt.Errorf("failed to construct status list URI: %w", err)
	}

	reply := &apiv1_registry.TokenStatusListAddStatusReply{
		Section:       section,
		Index:         index,
		StatusListUri: baseURL.String(),
	}

	return reply, nil
}

// TokenStatusListUpdate updates an existing status entry in the Token Status List
func (s *Service) TokenStatusListUpdateStatus(ctx context.Context, req *apiv1_registry.TokenStatusListUpdateStatusRequest) (*apiv1_registry.TokenStatusListUpdateStatusReply, error) {
	if req.Status > 255 {
		return nil, fmt.Errorf("status value %d exceeds uint8 range", req.Status)
	}
	err := s.tokenStatusListIssuer.UpdateStatus(ctx, req.Section, req.Index, uint8(req.Status))
	if err != nil {
		return nil, err
	}

	return &apiv1_registry.TokenStatusListUpdateStatusReply{}, nil
}

// SaveCredentialSubject saves credential subject info linked to a Token Status List entry
func (s *Service) SaveCredentialSubject(ctx context.Context, req *apiv1_registry.SaveCredentialSubjectRequest) (*apiv1_registry.SaveCredentialSubjectReply, error) {
	err := s.apiv1.SaveCredentialSubject(ctx, &apiv1.SaveCredentialSubjectRequest{
		Identifier: req.Identifier,
		Section:    req.Section,
		Index:      req.Index,
	})
	if err != nil {
		return nil, err
	}

	return &apiv1_registry.SaveCredentialSubjectReply{}, nil
}
