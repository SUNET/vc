package grpcserver

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/internal/issuer/apiv1"
)

// MakeSDJWT creates an sd-jwt and return it, else error
func (s *Service) MakeSDJWT(ctx context.Context, in *apiv1_issuer.MakeSDJWTRequest) (*apiv1_issuer.MakeSDJWTReply, error) {
	reply, err := s.apiv1.MakeSDJWT(ctx, &apiv1.CreateCredentialRequest{
		Scope:        in.Scope,
		DocumentData: in.DocumentData,
		JWK:          in.Jwk,
		Integrity:    in.Integrity,
		VCTM:         in.Vctm,
	})
	if err != nil {
		return nil, err
	}

	return &apiv1_issuer.MakeSDJWTReply{
		Credentials:            reply.Data,
		TokenStatusListSection: reply.TokenStatusListSection,
		TokenStatusListIndex:   reply.TokenStatusListIndex,
		TokenStatusListUri:     reply.TokenStatusListURI,
		TokenStatusListBackend: reply.TokenStatusListBackend,
		StatusAllocation:       statusAllocation(reply.TokenStatusListURI),
	}, nil
}

// JWKS returns the JWKS
func (s *Service) JWKS(ctx context.Context, in *apiv1_issuer.Empty) (*apiv1_issuer.JwksReply, error) {
	reply, err := s.apiv1.JWKS(ctx, in)
	if err != nil {
		return nil, err
	}

	return &apiv1_issuer.JwksReply{
		Issuer: reply.Issuer,
		Jwks:   reply.Jwks,
	}, nil
}

// MakeMDoc creates an mdoc credential per ISO 18013-5
func (s *Service) MakeMDoc(ctx context.Context, in *apiv1_issuer.MakeMDocRequest) (*apiv1_issuer.MakeMDocReply, error) {
	reply, err := s.apiv1.MakeMDoc(ctx, &apiv1.CreateMDocRequest{
		Scope:           in.Scope,
		DocumentData:    in.DocumentData,
		DevicePublicKey: in.DevicePublicKey,
		DeviceKeyFormat: in.DeviceKeyFormat,
		MDDL:            in.Mddl,
	})
	if err != nil {
		return nil, err
	}

	return &apiv1_issuer.MakeMDocReply{
		Mdoc:              reply.MDoc,
		StatusListSection: reply.StatusListSection,
		StatusListIndex:   reply.StatusListIndex,
		StatusListUri:     reply.StatusListURI,
		StatusListBackend: reply.StatusListBackend,
		StatusAllocation:  statusAllocation(reply.StatusListURI),
		ValidFrom:         reply.ValidFrom,
		ValidUntil:        reply.ValidUntil,
	}, nil
}

// SignMetadata signs metadata JSON with the issuer's own key (the key in JWKS)
func (s *Service) SignMetadata(ctx context.Context, in *apiv1_issuer.SignMetadataRequest) (*apiv1_issuer.SignMetadataReply, error) {
	return s.apiv1.SignMetadata(ctx, in)
}

// GetIACAs returns the IACA certificates from the mDOC certificate chain
func (s *Service) GetIACAs(ctx context.Context, _ *apiv1_issuer.Empty) (*apiv1_issuer.GetIACAsReply, error) {
	return s.apiv1.GetIACAs(ctx)
}

// Status returns the readiness status of the issuer service and its
// dependencies.
func (s *Service) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	return s.apiv1.Health(ctx, req)
}

// SetCredentialStatus writes a new status-list value for an already-issued
// credential, routing to whichever backend allocated the entry.
func (s *Service) SetCredentialStatus(ctx context.Context, in *apiv1_issuer.SetCredentialStatusRequest) (*apiv1_issuer.SetCredentialStatusReply, error) {
	if in == nil {
		return nil, fmt.Errorf("request is required")
	}
	if in.Status > 255 {
		return nil, fmt.Errorf("status value %d exceeds uint8 range", in.Status)
	}
	if err := s.apiv1.SetCredentialStatus(ctx, &apiv1.SetCredentialStatusRequest{
		Backend:       in.Backend,
		StatusListURI: in.StatusListUri,
		Section:       in.Section,
		Index:         in.Index,
		Status:        uint8(in.Status),
	}); err != nil {
		return nil, err
	}
	return &apiv1_issuer.SetCredentialStatusReply{}, nil
}

// statusAllocation says EXPLICITLY whether an entry was allocated, so the
// apigw never infers it from zero values - a registry's first allocation is
// legitimately section 0, index 0, which is indistinguishable from "nothing
// was allocated" unless somebody says which it is.
//
// The URI is the signal because the issuer's own invariant makes it one:
// allocateOrDegrade and allocateOptionalStatus both hand the slot back and
// return nothing when an allocation arrives without a URI, so a URI is
// present exactly when an entry was allocated.
func statusAllocation(uri string) apiv1_issuer.StatusAllocation {
	if uri == "" {
		return apiv1_issuer.StatusAllocation_STATUS_ALLOCATION_NONE
	}
	return apiv1_issuer.StatusAllocation_STATUS_ALLOCATION_ALLOCATED
}
