package httpserver

import (
	"context"
	"io"
	"net/http"

	"github.com/SUNET/vc/internal/verifier/apiv1"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
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

	request := &apiv1.UIInteractionRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	// Reuse hint priority: body wins over cookie. A body value is a client
	// that remembers its own session (e.g. sessionStorage after a reload);
	// the cookie is a shared per-origin fallback that a concurrent tab can
	// silently overwrite. If neither is set, apiv1 mints a fresh id.
	if request.SessionID == "" {
		if cookieSessionID, ok := session.Get("session_id").(string); ok && cookieSessionID != "" {
			request.SessionID = cookieSessionID
		}
	}

	reply, err := s.apiv1.UIInteraction(ctx, request)
	if err != nil {
		return nil, err
	}

	if cookieSessionID, _ := session.Get("session_id").(string); cookieSessionID != reply.SessionID {
		session.Set("session_id", reply.SessionID)
		if err := session.Save(); err != nil {
			s.log.Error(err, "failed to save session")
		}
	}

	return reply, nil
}

// endpointUINotify handles SSE connections for real-time notifications
func (s *Service) endpointUINotify(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUINotify")

	// A ?session_id= query param wins over the cookie so a reloaded tab
	// can subscribe to the id it remembers even if another tab in the
	// same origin has meanwhile overwritten the cookie.
	sessionID := c.Query("session_id")
	if sessionID == "" {
		session := sessions.Default(c)
		if cookieSessionID, ok := session.Get("session_id").(string); ok {
			sessionID = cookieSessionID
		}
	}
	if sessionID == "" {
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
