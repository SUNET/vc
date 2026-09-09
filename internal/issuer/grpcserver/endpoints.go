package grpcserver

import (
	"context"

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
