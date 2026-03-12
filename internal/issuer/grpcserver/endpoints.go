package grpcserver

import (
	"context"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/issuer/apiv1"
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
		Credentials:       reply.Data,
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

// MakeMDoc creates an mDL credential per ISO 18013-5
func (s *Service) MakeMDoc(ctx context.Context, in *apiv1_issuer.MakeMDocRequest) (*apiv1_issuer.MakeMDocReply, error) {
	reply, err := s.apiv1.MakeMDoc(ctx, &apiv1.CreateMDocRequest{
		Scope:           in.Scope,
		DocType:         in.DocType,
		DocumentData:    in.DocumentData,
		DevicePublicKey: in.DevicePublicKey,
		DeviceKeyFormat: in.DeviceKeyFormat,
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
