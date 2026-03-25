package httpserver

import (
	"context"
	"io"
	"net/http"
	"github.com/SUNET/vc/internal/verifier/apiv1"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointIndex(ctx context.Context, c *gin.Context) (any, error) {
	_, span := s.tracer.Start(ctx, "httpserver:endpointIndex")
	defer span.End()

	c.HTML(http.StatusOK, "presentation-definition.html", nil)

	return nil, nil
}

func (s *Service) endpointUIMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUIMetadata")
	defer span.End()

	reply, err := s.apiv1.UIMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointUIInteraction(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUIInteraction")

	session := sessions.Default(c)
	sessionID := uuid.NewString()
	session.Set("session_id", sessionID)
	session.Save()

	request := &apiv1.UIInteractionRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	// Pass session ID to apiv1
	request.SessionID = sessionID

	reply, err := s.apiv1.UIInteraction(ctx, request)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// endpointUINotify handles SSE connections for real-time notifications
func (s *Service) endpointUINotify(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUINotify")

	session := sessions.Default(c)

	sessionID, ok := session.Get("session_id").(string)
	if !ok {
		s.log.Error(nil, "session_id not found in session")
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id not found"})
		return nil, nil
	}
	s.log.Debug("notifyEndpoint", "sessionID", sessionID)

	listener := s.notify.OpenListener(sessionID)

	defer func() {
		s.log.Debug("endpointUINotify closing listener", "sessionID", sessionID)
		s.notify.CloseListener(sessionID, listener)
	}()

	// Set SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	c.Stream(func(w io.Writer) bool {
		select {
		case msg := <-listener:
			s.log.Debug("endpointUINotify", "msg", msg)
			c.SSEvent("message", msg)
			return true
		case <-c.Request.Context().Done():
			s.log.Debug("endpointUINotify client disconnected", "sessionID", sessionID)
			return false
		}
	})

	return nil, nil
}
