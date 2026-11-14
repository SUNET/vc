package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/helpers"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointResetUniqueCommitment removes the commitment on record for a key
// value, with the authenticated operator's approval on record. Every call
// is logged with its outcome.
func (s *Service) endpointResetUniqueCommitment(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointResetUniqueCommitment")
	defer span.End()

	operator, ok := operatorOf(c)
	if !ok {
		err := helpers.NewErrorDetailsWithStatus("operator_required",
			"a reset is approved by an authenticated operator", http.StatusForbidden)
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "unique commitment reset refused")
		return nil, err
	}
	// The authorization middleware reads scope from the body by its exact
	// key, so a body the binder could read differently is refused.
	if err := requireCanonicalJSONBody(c, "scope", "path", "key", "evidence_ref"); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "ambiguous request body")
		return nil, err
	}
	request := &apiv1.ResetUniqueCommitmentRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "binding error")
		return nil, err
	}

	err := s.apiv1.ResetUniqueCommitment(ctx, request, operator)
	// Key values can be personal data, so the log names the entry and the
	// approval.
	s.log.Info("unique commitment reset", "scope", request.Scope, "path", request.Path,
		"approved_by", operator, "evidence_ref", request.EvidenceRef, "reset", err == nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}

// endpointLookupUniqueCommitment tells when the commitment of a key value
// was recorded. Every call is logged.
func (s *Service) endpointLookupUniqueCommitment(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointLookupUniqueCommitment")
	defer span.End()

	// The authorization middleware reads scope from the body by its exact
	// key, so a body the binder could read differently is refused.
	if err := requireCanonicalJSONBody(c, "scope", "path", "key"); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "ambiguous request body")
		return nil, err
	}
	request := &apiv1.UniqueCommitmentQuery{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "binding error")
		return nil, err
	}

	reply, err := s.apiv1.LookupUniqueCommitment(ctx, request)
	operator, _ := operatorOf(c)
	s.log.Info("unique commitment lookup", "scope", request.Scope, "path", request.Path,
		"operator", operator, "found", err == nil)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}
