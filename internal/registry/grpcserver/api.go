package grpcserver

import (
	"context"

	"github.com/SUNET/vc/internal/registry/apiv1"
)

// TokenStatusListIssuer interface for Token Status List operations
type TokenStatusListIssuer interface {
	AddStatus(ctx context.Context, status uint8) (int64, int64, error)
	UpdateStatus(ctx context.Context, section int64, index int64, status uint8) error
}

// Apiv1 interface for the apiv1 client methods used by grpcserver
type Apiv1 interface {
	SaveCredentialSubject(ctx context.Context, req *apiv1.SaveCredentialSubjectRequest) error
}
