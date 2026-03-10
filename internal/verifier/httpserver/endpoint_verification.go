package httpserver

import (
	"context"
	"net/http"
	"vc/internal/verifier/apiv1"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func (s *Service) endpointVerificationRequestObject(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointVerificationRequestObject called")

	request := &apiv1.VerificationRequestObjectRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.VerificationRequestObject(ctx, request)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointVerificationDirectPost(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointVerificationDirectPost called")

	request := &apiv1.VerificationDirectPostRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}
	s.log.Debug("endpointVerificationDirectPost", "here", "after binding")

	// Check if this is a same-device flow by looking for session_id
	session := sessions.Default(c)
	if sessionID, ok := session.Get("session_id").(string); ok && sessionID != "" {
		request.SessionID = sessionID
		s.log.Debug("endpointVerificationDirectPost", "same_device_flow", true, "session_id", sessionID)
	}

	reply, err := s.apiv1.VerificationDirectPost(ctx, request)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointVerificationCallback(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointVerificationCallback called")

	request := &apiv1.VerificationCallbackRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.VerificationCallback(ctx, request)
	if err != nil {
		s.log.Error(err, "Failed to get verification callback reply")
	}

	c.HTML(http.StatusOK, "callback.html", reply)

	return nil, nil
}

func (s *Service) endpointVerifyZKP(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointVerificationDirectPost called")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2*1024*1024)
	request := &apiv1.VerifyZKPRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		s.log.Error(err, "binding failed")
		return nil, err
	}
	reply, err := s.apiv1.VerifyZKP(ctx, request)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
