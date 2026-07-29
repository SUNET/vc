package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointUserAuthenticSourceLookup(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUserAuthenticSourceLookup")
	defer span.End()
	session := sessions.Default(c)

	sessionID, ok := session.Get("session_id").(string)
	if !ok {
		err := errors.New("session_id not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserAuthenticSourceLookup: session_id not found in session")
		return nil, err
	}

	reply, err := s.apiv1.UserAuthenticSourceLookup(ctx, &vcclient.UserAuthenticSourceLookupRequest{
		SessionID: sessionID,
	})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserAuthenticSourceLookup: error looking up authentic sources")
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointUserLookup(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUserLookup")
	defer span.End()
	session := sessions.Default(c)

	scope, ok := session.Get("scope").(string)
	if !ok {
		err := errors.New("scope not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserLookup: scope not found in session")
		return nil, err
	}

	vctm, err := s.apiv1.GetVCTMFromScope(ctx, &apiv1.GetVCTMFromScopeRequest{Scope: scope})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserLookup: error getting VCTM from scope")
		return nil, err
	}

	var mddl *mdoc.MDDLSchema
	if vctm == nil {
		mddl, err = s.apiv1.GetMDDLFromScope(ctx, &apiv1.GetMDDLFromScopeRequest{Scope: scope})
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			s.log.Error(err, "endpointUserLookup: error getting MDDL from scope")
			return nil, err
		}
	}

	requestURI, ok := session.Get("request_uri").(string)
	if !ok {
		err := errors.New("request_uri not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserLookup: request_uri not found in session")
		return nil, err
	}

	s.log.Debug("endpointUserLookup", "requestURI", requestURI)

	request := &vcclient.UserLookupRequest{
		RequestURI: requestURI,
	}

	authProvider, ok := session.Get("auth_provider").(string)
	if !ok {
		err := errors.New("auth_provider not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserLookup: auth_provider not found in session")
		return nil, err
	}

	request.AuthProvider = authProvider
	request.VCTM = vctm
	request.MDDL = mddl

	switch authProvider {
	case model.AuthProviderOpenID4VP:
		responseCode, ok := session.Get("response_code").(string)
		if !ok {
			err := errors.New("response_code not found in session")
			span.SetStatus(codes.Error, err.Error())
			s.log.Error(err, "endpointUserLookup: response_code not found in session")
			return nil, err
		}
		request.ResponseCode = responseCode

	case model.AuthProviderSAML, model.AuthProviderOIDC:
		// For SAML/OIDC auth methods, documents are already stored in the VCI
		// session cache by the ACS/callback handlers. No additional session data
		// is needed — the apiv1 UserLookup will retrieve them using the session ID
		// from the authorization context (same as pid_auth's default cache path).
		s.log.Debug("endpointUserLookup: SAML/OIDC auth method, documents in VCI cache",
			"auth_provider", authProvider)

	default:
		err := errors.New("unsupported auth method for user lookup")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserLookup: unsupported auth provider", "auth_provider", authProvider)
		return nil, err
	}

	reply, err := s.apiv1.UserLookup(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointUserCancel(ctx context.Context, c *gin.Context) (any, error) {
	_, span := s.tracer.Start(ctx, "httpserver:endpointUserCancel")
	defer span.End()

	session := sessions.Default(c)

	walletClientID, ok := session.Get("wallet_client_id").(string)
	if !ok {
		err := errors.New("wallet_client_id not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserCancel: wallet_client_id not found in session")
		return nil, err
	}

	session.Clear()

	if err := session.Save(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "session save error")
		return nil, err
	}

	client, ok := s.cfg.APIGW.Delivery.OpenID4VCI.Clients[walletClientID]
	if !ok {
		err := errors.New("invalid wallet_client_id")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "endpointUserCancel: invalid wallet_client_id", "wallet_client_id", walletClientID)
		return nil, err
	}

	if len(client.RedirectURIs) == 0 {
		err := errors.New("no redirect_uri configured for client")
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	// NOTE: The original redirect_uri from the authorization request is not stored in the session,
	// so we fall back to the first concrete (non-wildcard) URI. This is safe because all registered
	// redirect URIs belong to the same client and the cancel response carries no authorization data.
	cancelURI := client.RedirectURIs.FirstConcreteURI()
	if cancelURI == "" {
		err := errors.New("no concrete redirect_uri configured for client")
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	c.Redirect(http.StatusSeeOther, cancelURI)

	return nil, nil
}
