package grpcserver

import (
	"context"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/internal/issuer/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	MakeSDJWT(ctx context.Context, req *apiv1.CreateCredentialRequest) (*apiv1.CreateCredentialReply, error)
	MakeMDoc(ctx context.Context, req *apiv1.CreateMDocRequest) (*apiv1.CreateMDocReply, error)
	JWKS(ctx context.Context, req *apiv1_issuer.Empty) (*apiv1_issuer.JwksReply, error)

	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
