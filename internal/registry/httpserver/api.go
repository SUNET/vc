package httpserver

import (
	"context"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/internal/registry/apiv1"
)

// Apiv1 interface
type Apiv1 interface {
	Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)

	// Token Status List endpoints
	TokenStatusLists(ctx context.Context, req *apiv1.TokenStatusListsRequest) (*apiv1.TokenStatusListsResponse, error)
	TokenStatusListAggregation(ctx context.Context) (*apiv1.TokenStatusListAggregationResponse, error)

	// Admin GUI endpoints
	SearchPerson(ctx context.Context, req *apiv1.SearchPersonRequest) (*apiv1.SearchPersonReply, error)
	UpdateStatus(ctx context.Context, req *apiv1.UpdateStatusRequest) error
}
