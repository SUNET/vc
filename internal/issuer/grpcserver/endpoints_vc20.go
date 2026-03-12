package grpcserver

import (
	"context"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/issuer/apiv1"
)

// MakeVC20 creates a W3C VC 2.0 Data Integrity credential
func (s *Service) MakeVC20(ctx context.Context, in *apiv1_issuer.MakeVC20Request) (*apiv1_issuer.MakeVC20Reply, error) {
	reply, err := s.apiv1VC20().MakeVC20(ctx, &apiv1.CreateVC20Request{
		Scope:             in.Scope,
		DocumentData:      in.DocumentData,
		CredentialTypes:   in.CredentialTypes,
		SubjectDID:        in.SubjectDid,
		Cryptosuite:       in.Cryptosuite,
		MandatoryPointers: in.MandatoryPointers,
	})
	if err != nil {
		return nil, err
	}

	return &apiv1_issuer.MakeVC20Reply{
		Credential:        reply.Credential,
		CredentialId:      reply.CredentialID,
		StatusListSection: reply.StatusListSection,
		StatusListIndex:   reply.StatusListIndex,
		ValidFrom:         reply.ValidFrom,
		ValidUntil:        reply.ValidUntil,
	}, nil
}
