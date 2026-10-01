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

	// Only the body is a reuse hint. The gin cookie is per-origin and
	// shared across tabs, so a brand-new tab that has no sessionStorage
	// but inherits a sibling's cookie would silently rejoin that
	// sibling's authorization context - two tabs subscribed to the same
	// wallet result, or (on a changed DCQL) the sibling's context
	// replaced by a fresh one. The reuse path must be driven by the
	// tab-scoped channel only; the cookie keeps its original purpose
	// (SSE listener lookup, session-preference compat).
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

	sessionID := resolveNotifySessionID(c)
	if sessionID == "" {
		s.log.Error(nil, "session_id not found in session")
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id not found"})
		return nil, nil
	}

	// Refuse to open a listener for an id the verifier does not know
	// about. notify.Service.OpenListener would otherwise create a
	// broadcaster entry per request, which an unauthenticated caller
	// can turn into unbounded growth of the process-wide map.
	if !s.apiv1.IsActiveAuthSession(ctx, sessionID) {
		s.log.Debug("endpointUINotify unknown session_id", "sessionID", sessionID)
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown session_id"})
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

// resolveNotifySessionID picks the session_id for /ui/notify. A
// ?session_id= query param wins over the gin cookie session so a reloaded
// tab (or a second tab that remembered its id in sessionStorage) can
// rejoin its own authorization context even after another tab in the same
// origin overwrote the shared cookie.
func resolveNotifySessionID(c *gin.Context) string {
	if id := c.Query("session_id"); id != "" {
		return id
	}
	if cookieSessionID, ok := sessions.Default(c).Get("session_id").(string); ok {
		return cookieSessionID
	}
	return ""
}
