package httpserver

import (
	"context"
	"errors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"time"
	apiv1_apigw "vc/internal/apigw/apiv1"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/ui/apiv1"
)

func (s *Service) endpointStatus(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Status(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointLogin(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.LoginRequest{}
	if err := c.ShouldBindJSON(&request); err != nil {
		//if err := s.bindRequest(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.Login(ctx, request)
	if err != nil {
		return nil, err
	}

	session := sessions.Default(c)
	session.Set(s.sessionConfig.usernameKey, reply.Username)
	session.Set(s.sessionConfig.loggedInTimeKey, reply.LoggedInTime)
	if err := session.Save(); err != nil { //This is also where the session cookie is created by gin
		s.logger.Error(err, "Failed to save session (and send cookie) during login")
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointLogout(ctx context.Context, c *gin.Context) (any, error) {
	session := sessions.Default(c)
	username := session.Get(s.sessionConfig.usernameKey)
	if username == nil {
		return nil, errors.New("invalid session token")
	}

	session.Clear()
	session.Options(sessions.Options{
		MaxAge:   -1, // Expired
		Path:     s.sessionConfig.path,
		Secure:   s.sessionConfig.secure,
		HttpOnly: s.sessionConfig.httpOnly,
		SameSite: s.sessionConfig.sameSite,
	})
	if err := session.Save(); err != nil { //Save the cleared session and send remove session cookie to browser
		return nil, errors.New("failed to remove session (and cookie)")
	}

	return nil, nil
}

func (s *Service) endpointUser(ctx context.Context, c *gin.Context) (any, error) {
	session := sessions.Default(c)

	username, ok := session.Get(s.sessionConfig.usernameKey).(string)
	if !ok {
		return nil, errors.New("failed to convert username to string")
	}

	loggedInTime, ok := session.Get(s.sessionConfig.loggedInTimeKey).(time.Time)
	if !ok {
		return nil, errors.New("failed to convert logged in time to time.Time")
	}

	reply := &apiv1.LoggedinReply{
		Username:     username,
		LoggedInTime: loggedInTime,
	}

	return reply, nil
}

func (s *Service) endpointAPIGWStatus(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.StatusAPIGW(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointPortal(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.PortalRequest{}
	if err := c.ShouldBindJSON(&request); err != nil {
		//TODO: remove if err := s.bindRequest(ctx, c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.Portal(ctx, request)

	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointUpload(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_apigw.UploadRequest{}
	if err := c.ShouldBindJSON(&request); err != nil {
		//TODO: remove if err := s.bindRequest(ctx, c, request); err != nil {
		s.logger.Debug("Binding error", "error", err)
		return nil, err
	}

	reply, err := s.apiv1.Upload(ctx, request)

	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointMockNext(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.MockNextRequest{}
	if err := c.ShouldBindJSON(&request); err != nil {
		//TODO: remove if err := s.bindRequest(ctx, c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.MockNext(ctx, request)

	if err != nil {
		return nil, err
	}
	return reply, nil
}
