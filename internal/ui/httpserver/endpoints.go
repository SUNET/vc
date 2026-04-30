package httpserver

import (
	"context"
	"errors"
	"time"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/internal/ui/apiv1"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func (s *Service) endpointHealth(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Health(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointLogin(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.LoginRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
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
		s.log.Error(err, "Failed to save session (and send cookie) during login")
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

func (s *Service) endpointHealthAPIGW(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.HealthAPIGW(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointHealthVerifier(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.HealthVerifier(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointHealthMockAS(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.HealthMockAS(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointDocumentList(ctx context.Context, c *gin.Context) (any, error) {
	request := &vcclient.DocumentListQuery{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.DocumentList(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointUpload(ctx context.Context, c *gin.Context) (any, error) {
	request := &vcclient.UploadRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	err := s.apiv1.Upload(ctx, request)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *Service) endpointGetDocument(ctx context.Context, c *gin.Context) (any, error) {
	request := &vcclient.DocumentGetQuery{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.GetDocument(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointNotification(ctx context.Context, c *gin.Context) (any, error) {
	request := &vcclient.NotificationRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.Notification(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointMockNext(ctx context.Context, c *gin.Context) (any, error) {
	request := &vcclient.MockNextRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.MockNext(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointSearchDocuments(ctx context.Context, c *gin.Context) (any, error) {
	request := &model.SearchDocumentsRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	reply, err := s.apiv1.SearchDocuments(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointDeleteDocument(ctx context.Context, c *gin.Context) (any, error) {
	request := &vcclient.DocumentDeleteQuery{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		return nil, err
	}

	err := s.apiv1.DeleteDocument(ctx, request)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

