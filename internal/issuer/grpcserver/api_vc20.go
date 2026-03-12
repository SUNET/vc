package grpcserver

import (
	"context"
	"vc/internal/issuer/apiv1"
)

// Apiv1VC20 extends the Apiv1 interface with W3C VC 2.0 support
type Apiv1VC20 interface {
	Apiv1
	MakeVC20(ctx context.Context, req *apiv1.CreateVC20Request) (*apiv1.CreateVC20Reply, error)
}

// apiv1VC20 returns the Apiv1 interface cast to Apiv1VC20
// This will panic at runtime if the apiv1 implementation doesn't support VC20
func (s *Service) apiv1VC20() Apiv1VC20 {
	return s.apiv1.(Apiv1VC20)
}
