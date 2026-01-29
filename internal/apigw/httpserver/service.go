package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"
	"vc/internal/apigw/apiv1"
	"vc/internal/apigw/staticembed"
	"vc/pkg/crypto"
	"vc/pkg/httphelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/gin-contrib/sessions"

	// Swagger
	_ "vc/docs/apigw"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Service is the service object for httpserver
type Service struct {
	cfg             *model.Cfg
	log             *logger.Log
	server          *http.Server
	apiv1           Apiv1
	gin             *gin.Engine
	tracer          *trace.Tracer
	eventPublisher  apiv1.EventPublisher
	httpHelpers     *httphelpers.Client
	sessionsOptions sessions.Options
	sessionsEncKey  string
	sessionsAuthKey string
	sessionsName    string
	samlService     SAMLService
	oidcrpService   OIDCRPService
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, tracer *trace.Tracer, eventPublisher apiv1.EventPublisher, samlService SAMLService, oidcrpService OIDCRPService, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:    cfg,
		log:    log.New("httpserver"),
		apiv1:  apiv1,
		gin:    gin.New(),
		tracer: tracer,
		server: &http.Server{
			ReadHeaderTimeout: 3 * time.Second,
		},
		eventPublisher:  eventPublisher,
		samlService:     samlService,
		oidcrpService:   oidcrpService,
		sessionsName:    "oauth_user_session",
		sessionsOptions: sessions.Options{
			Path:     "/",
			Domain:   "",
			MaxAge:   900,
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	if s.cfg.APIGW.APIServer.TLS.Enabled {
		s.sessionsOptions.Secure = true
		//s.sessionsOptions.SameSite = http.SameSiteStrictMode
	}

	// Generate session keys
	var err error
	s.sessionsAuthKey, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session auth key: %w", err)
	}

	s.sessionsEncKey, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session encryption key: %w", err)
	}

	var httpHelpersErr error
	s.httpHelpers, httpHelpersErr = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if httpHelpersErr != nil {
		return nil, httpHelpersErr
	}

	// Used in development to avoid bundling static files in the executable.
	// When used, comment the four lines below these ones.
	// s.gin.Static("/static", "./staticembed")
	// s.gin.LoadHTMLGlob("./staticembed/*.html")

	s.gin.StaticFS("/static", http.FS(staticembed.FS))

	// Create a new template with custom functions before parsing
	t := template.New("").Funcs(template.FuncMap{
		"json": func(v any) (any, error) {
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			// Return as template.JS to prevent escaping in JavaScript context
			return template.JS(string(jsonBytes)), nil
		},
	})

	f := template.Must(t.ParseFS(staticembed.FS, "*.html"))

	s.gin.SetHTMLTemplate(f)

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.APIGW.APIServer.Addr)
	if err != nil {
		return nil, err
	}

	// Configure CORS from config if present and has origins
	if s.cfg.APIGW.APIServer.CORS != nil && len(s.cfg.APIGW.APIServer.CORS.AllowedOrigins) > 0 {
		corsConfig := cors.Config{
			AllowOrigins:     s.cfg.APIGW.APIServer.CORS.AllowedOrigins,
			AllowMethods:     []string{"GET", "POST", "OPTIONS"},
			AllowHeaders:     []string{"Content-Type", "Authorization"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour,
		}
		rgRoot.Use(cors.New(corsConfig))
	}

	rgRestricted, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.APIGW.APIServer.Addr)
	if err != nil {
		return nil, err
	}

	rgRestricted.Use(s.httpHelpers.Middleware.BasicAuth(ctx, s.cfg.APIGW.APIServer.BasicAuth.Users))

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "/", http.StatusOK, s.endpointIndex)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "offers", http.StatusOK, s.endpointUICredentialOffers)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "offers/:scope/:wallet_id", http.StatusOK, s.endpointUICreateCredentialOffer)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "nonce", http.StatusOK, s.endpointOIDCNonce)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "credential", http.StatusOK, s.endpointOIDCCredential)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "credential-offer/:credential_offer_uuid", http.StatusOK, s.endpointOIDCredentialOfferURI)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "deferred_credential", http.StatusOK, s.endpointOIDCDeferredCredential)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRestricted, http.MethodPost, "notification", http.StatusNoContent, s.endpointOIDCNotification)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/openid-credential-issuer", http.StatusOK, s.endpointOIDCMetadata)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/oauth-authorization-server", http.StatusOK, s.endpointOAuthMetadata)
	rgOAuthSession := rgRoot.Group("")
	rgOAuthSession.Use(s.httpHelpers.Middleware.UserSession(s.sessionsName, s.sessionsAuthKey, s.sessionsEncKey, s.sessionsOptions))
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "op/par", http.StatusCreated, s.endpointOAuthPar)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorize", http.StatusPermanentRedirect, s.endpointOAuthAuthorize)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorization/consent", http.StatusNotModified, s.endpointOAuthAuthorizationConsent)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorization/consent/callback", http.StatusNotModified, s.endpointOAuthAuthorizationConsentCallback)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorization/consent/svg-template", http.StatusOK, s.endpointOAuthAuthorizationConsentSvgTemplate)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "token", http.StatusOK, s.endpointOAuthToken)

	// Register SAML endpoints if enabled (build tag dependent)
	s.registerSAMLRoutes(ctx, rgRoot)

	// Register OIDC RP endpoints if enabled (build tag dependent)
	s.registerOIDCRPRoutes(ctx, rgRoot)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", 200, s.endpointHealth)

	rgDocs := rgRoot.Group("/swagger")
	rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	rgAPIv1 := rgRoot.Group("api/v1")

	if s.cfg.APIGW.APIServer.BasicAuth.Enabled {
		rgAPIv1.Use(s.httpHelpers.Middleware.BasicAuth(ctx, s.cfg.APIGW.APIServer.BasicAuth.Users))
	}

	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/upload", http.StatusOK, s.endpointUpload)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/notification", http.StatusOK, s.endpointNotification)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPut, "/document/identity", http.StatusOK, s.endpointAddDocumentIdentity)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodDelete, "/document/identity", http.StatusOK, s.endpointDeleteDocumentIdentity)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodDelete, "/document", http.StatusOK, s.endpointDeleteDocument)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/collect_id", http.StatusOK, s.endpointGetDocumentCollectID)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/identity/mapping", http.StatusOK, s.endpointIdentityMapping)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/list", http.StatusOK, s.endpointDocumentList)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document", http.StatusOK, s.endpointGetDocument)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/search", http.StatusOK, s.endpointSearchDocuments)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/consent", http.StatusOK, s.endpointAddConsent)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/consent/get", http.StatusOK, s.endpointGetConsent)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/revoke", http.StatusOK, s.endpointRevokeDocument)

	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/user/pid", http.StatusOK, s.endpointAddPIDUser)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "/user/pid/login", http.StatusOK, s.endpointLoginPIDUser)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "/user/lookup", http.StatusOK, s.endpointUserLookup)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "/user/cancel", http.StatusSeeOther, s.endpointUserCancel)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "/user/authentic_source/lookup", http.StatusOK, s.endpointUserAuthenticSourceLookup)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "/user/authentic_source/lookup", http.StatusOK, s.endpointUserAuthenticSourceLookup)

	//verification endpoints
	rgVerification := rgRoot.Group("/verification")
	s.httpHelpers.Server.RegEndpoint(ctx, rgVerification, http.MethodGet, "/request-object", http.StatusOK, s.endpointVerificationRequestObject)
	s.httpHelpers.Server.RegEndpoint(ctx, rgVerification, http.MethodPost, "/direct_post", http.StatusOK, s.endpointVerificationDirectPost)

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.APIGW.APIServer)
		if err != nil {
			s.log.Trace("listen_error", "error", err)
		}
	}()

	s.log.Info("Started")

	return s, nil
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopped")
	return nil
}
