package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/internal/registry/apiv1"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointRootRedirect(ctx context.Context, c *gin.Context) (any, error) {
	c.Redirect(http.StatusFound, "/admin/login")
	return nil, nil
}

func (s *Service) endpointHealth(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Status(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// endpointStatusLists handles GET /statuslists/:id
// Returns a Status List Token (JWT or CWT) for the specified section.
func (s *Service) endpointStatusLists(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.TokenStatusListsRequest{}

	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.TokenStatusLists(ctx, request)
	if err != nil {
		return nil, err
	}

	// Set Content-Type header (application/statuslist+jwt or application/statuslist+cwt)
	c.Header("Content-Type", reply.ContentType)

	return reply, nil
}

// endpointTokenStatusListAggregation handles GET /.well-known/statuslist-aggregation
// Returns a JSON array of URIs linking to all Status List Tokens.
func (s *Service) endpointTokenStatusListAggregation(ctx context.Context, c *gin.Context) (any, error) {
	reply, err := s.apiv1.TokenStatusListAggregation(ctx)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
