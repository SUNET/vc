package grpcserver

import (
	"context"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/internal/issuer/apiv1"
)

// MakeJWP creates a blind BBS credential in JWP Compact Serialization
func (s *Service) MakeJWP(ctx context.Context, in *apiv1_issuer.MakeJWPRequest) (*apiv1_issuer.MakeJWPReply, error) {
	reply, err := s.apiv1.MakeJWP(ctx, &apiv1.CreateJWPRequest{
		Scope:          in.Scope,
		DocumentData:   in.DocumentData,
		Commitment:     in.Commitment,
		HolderPointers: in.HolderPointers,
		VCT:            in.Vct,
		KeyBinding:     in.KeyBinding,
	})
	if err != nil {
		return nil, err
	}

	return &apiv1_issuer.MakeJWPReply{
		Credentials:            reply.Data,
		TokenStatusListSection: reply.TokenStatusListSection,
		TokenStatusListIndex:   reply.TokenStatusListIndex,
	}, nil
}
