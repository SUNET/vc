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

// endpointUIResult returns the verified credential data for a response_code
// as JSON, so the verifier UI can render it inline (and survive an F5
// reload) instead of navigating away to the HTML callback page.
func (s *Service) endpointUIResult(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUIResult")
	defer span.End()

	// Verified credential claims are sensitive and expire with the server
	// cache; forbid browser and intermediary caching on both success and
	// error paths. Set before any write so the framework's JSON write
	// cannot flush the response ahead of them.
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	request := &apiv1.VerificationCallbackRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.VerificationCallback(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.JSON(http.StatusNotFound, gin.H{"error": "result not available"})
		return nil, nil
	}

	return reply, nil
}

// endpointUICompletion lets a reloaded verifier UI recover the
// response_code of a session the wallet already answered. The SSE
// redirect_uri is a one-shot message; without this a reload between
// "wallet shared" and "SSE delivered" would drop the user back on the
// preset menu with the result still cached server-side.
func (s *Service) endpointUICompletion(ctx context.Context, c *gin.Context) (any, error) {
	_, span := s.tracer.Start(ctx, "httpserver:endpointUICompletion")
	defer span.End()

	sessionID := c.Query("session_id")
	if sessionID == "" {
		if cookieSessionID, ok := sessions.Default(c).Get("session_id").(string); ok {
			sessionID = cookieSessionID
		}
	}
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id required"})
		return nil, nil
	}

	responseCode := s.apiv1.CompletedResponseCode(ctx, sessionID)
	if responseCode == "" {
		c.JSON(http.StatusOK, gin.H{"status": "pending"})
		return nil, nil
	}
	return gin.H{"status": "complete", "response_code": responseCode}, nil
}

// endpointUIResume rebuilds the state of a verifier UI reloaded mid-flow.
// Returns the still-pending QR / request_uri when the wallet has not
// answered yet, or the response_code when it already has, so the user
// stays on their original screen across F5 instead of landing on the
// preset menu with no indication of what was happening.
func (s *Service) endpointUIResume(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUIResume")
	defer span.End()

	sessionID := c.Query("session_id")
	if sessionID == "" {
		if cookieSessionID, ok := sessions.Default(c).Get("session_id").(string); ok {
			sessionID = cookieSessionID
		}
	}
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id required"})
		return nil, nil
	}

	reply, err := s.apiv1.UIResume(ctx, sessionID)
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
		case msg, ok := <-listener:
			// A closed listener (service shutdown or lifecycle reclaim)
			// would otherwise fire this case repeatedly with a nil msg
			// and spin until the client disconnects.
			if !ok {
				s.log.Debug("endpointUINotify listener closed", "sessionID", sessionID)
				return false
			}
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
