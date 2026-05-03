package httpserver

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	authproviders "github.com/SUNET/vc/internal/apigw/auth_providers"
	"github.com/SUNET/vc/internal/apigw/cache"
	datasources "github.com/SUNET/vc/internal/apigw/data_sources"
	"github.com/SUNET/vc/internal/apigw/staticembed"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-contrib/sessions"

	// Swagger
	_ "github.com/SUNET/vc/docs/apigw"

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
	authProviders   *authproviders.Service
	dataSources     *datasources.Service
	cacheService    *cache.Service
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, tracer *trace.Tracer, eventPublisher apiv1.EventPublisher, authProviders *authproviders.Service, dataSources *datasources.Service, cacheService *cache.Service, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:            cfg,
		log:            log.New("httpserver"),
		apiv1:          apiv1,
		gin:            gin.New(),
		tracer:         tracer,
		server:         &http.Server{}, //#nosec G112 -- ReadHeaderTimeout set by httphelpers.Server.Default
		eventPublisher: eventPublisher,
		authProviders:  authProviders,
		dataSources:    dataSources,
		sessionsName:   "oauth_user_session",
		sessionsOptions: sessions.Options{
			Path:     "/",
			Domain:   "",
			MaxAge:   900,
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	if s.cfg.APIGW.APIServer.TLS.Enable {
		s.sessionsOptions.Secure = true
	}

	// Session keys resolved by the cache service (HA-shared or ephemeral).
	s.sessionsAuthKey = cacheService.SessionAuthKey
	s.sessionsEncKey = cacheService.SessionEncKey
	s.cacheService = cacheService

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
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
			return template.JS(string(jsonBytes)), nil //#nosec G203 -- json.Marshal output is safe
		},
	})

	f := template.Must(t.ParseFS(staticembed.FS, "*.html"))

	s.gin.SetHTMLTemplate(f)

	// Configure CORS at the engine level (before route registration) so that
	// OPTIONS preflight requests are handled correctly. Placing CORS on a
	// router group causes preflight requests to hit Gin's NoRoute handler
	// (404) because no explicit OPTIONS route is registered.
	if s.cfg.APIGW.APIServer.CORS != nil && len(s.cfg.APIGW.APIServer.CORS.AllowedOrigins) > 0 {
		corsConfig := cors.Config{
			AllowOrigins:     s.cfg.APIGW.APIServer.CORS.AllowedOrigins,
			AllowMethods:     []string{"GET", "POST", "OPTIONS"},
			AllowHeaders:     []string{"Content-Type", "Authorization", "DPoP"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour,
			// Allow any origin for SAML and OIDC callback paths. These
			// endpoints receive cross-origin POSTs/redirects from external
			// IdPs via browser form submissions (SAML POST binding). The
			// IdP origin is dynamic and CORS does not apply to navigations,
			// but the browser still sends an Origin header which the CORS
			// middleware would otherwise reject with 403.
			AllowOriginWithContextFunc: func(c *gin.Context, origin string) bool {
				return strings.HasPrefix(c.Request.URL.Path, "/samlsp/") ||
					strings.HasPrefix(c.Request.URL.Path, "/oidcrp/")
			},
		}
		s.gin.Use(cors.New(corsConfig))
	}
	// If no CORS configuration is provided, do not enable CORS middleware by default.
	// This avoids unintentionally allowing cross-origin access when operators have
	// not explicitly configured allowed origins.

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.APIGW.APIServer)
	if err != nil {
		return nil, err
	}

	rgRestricted := rgRoot.Group("/")
	rgRestricted.Use(s.httpHelpers.Middleware.APIAuth(ctx, "apigw", s.cfg.APIGW.APIServer.APIAuth, cacheService.JWKS))

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "/", http.StatusOK, s.endpointIndex)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "offers", http.StatusOK, s.endpointUICredentialOffers)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "offers/:scope/:wallet_id", http.StatusOK, s.endpointUICreateCredentialOffer)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "nonce", http.StatusOK, s.endpointVCINonce)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "credential", http.StatusOK, s.endpointVCICredential)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "credential-offer/:credential_offer_uuid", http.StatusOK, s.endpointVCICredentialOfferURI)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "deferred_credential", http.StatusOK, s.endpointVCIDeferredCredential)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRestricted, http.MethodPost, "notification", http.StatusNoContent, s.endpointVCINotification)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/openid-credential-issuer", http.StatusOK, s.endpointVCIMetadata)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/oauth-authorization-server", http.StatusOK, s.endpointOAuthMetadata)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/jwt-vc-issuer", http.StatusOK, s.endpointSDJWTVCIssuerMetadata)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "jwks", http.StatusOK, s.endpointJWKS)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "type-metadata/:scope", http.StatusOK, s.endpointTypeMetadata)
	rgOAuthSession := rgRoot.Group("")
	rgOAuthSession.Use(s.httpHelpers.Middleware.UserSession(s.sessionsName, s.sessionsAuthKey, s.sessionsEncKey, s.sessionsOptions))
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "op/par", http.StatusCreated, s.endpointOAuthPar)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorize", http.StatusPermanentRedirect, s.endpointOAuthAuthorize)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorization/consent", http.StatusNotModified, s.endpointOAuthAuthorizationConsent)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorization/consent/callback", http.StatusNotModified, s.endpointOAuthAuthorizationConsentCallback)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodGet, "authorization/consent/svg-template", http.StatusOK, s.endpointOAuthAuthorizationConsentSvgTemplate)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "token", http.StatusOK, s.endpointOAuthToken)

	// SAML endpoints
	rgSAML := rgRoot.Group("/samlsp")
	s.httpHelpers.Server.RegEndpoint(ctx, rgSAML, http.MethodGet, "/metadata", http.StatusOK, s.endpointSAMLMetadata)
	s.httpHelpers.Server.RegEndpoint(ctx, rgSAML, http.MethodPost, "/initiate", http.StatusOK, s.endpointSAMLInitiate)
	s.httpHelpers.Server.RegEndpoint(ctx, rgSAML, http.MethodPost, "/acs", http.StatusOK, s.endpointSAMLACS)

	// OIDC RP endpoints
	rgOIDCRP := rgRoot.Group("/oidcrp")
	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCRP, http.MethodPost, "/initiate", http.StatusOK, s.endpointOIDCRPInitiate)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCRP, http.MethodGet, "/callback", http.StatusOK, s.endpointOIDCRPCallback)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", 200, s.endpointHealth)

	rgDocs := rgRoot.Group("/swagger")
	rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	rgAPIv1 := rgRoot.Group("api/v1")

	rgAPIv1.Use(s.httpHelpers.Middleware.APIAuth(ctx, "apigw", s.cfg.APIGW.APIServer.APIAuth, cacheService.JWKS))

	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/upload", http.StatusOK, s.endpointUpload)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/notification", http.StatusOK, s.endpointNotification)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPut, "/document/identity", http.StatusOK, s.endpointAddDocumentIdentity)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodDelete, "/document/identity", http.StatusOK, s.endpointDeleteDocumentIdentity)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/search", http.StatusOK, s.endpointSearchDocuments)

	// Streamlined identity mapping endpoints
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/identity/mapping", http.StatusOK, s.endpointCreateIdentityMapping)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/identity/mapping/resolve", http.StatusOK, s.endpointResolveIdentityMapping)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPut, "/identity/mapping", http.StatusOK, s.endpointUpdateIdentityMapping)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodDelete, "/identity/mapping", http.StatusOK, s.endpointDeleteIdentityMapping)

	// Streamlined document endpoints
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document", http.StatusOK, s.endpointUploadDocument)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodGet, "/document", http.StatusOK, s.endpointGetDocumentByKey)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/list", http.StatusOK, s.endpointListDocumentsByIdentifier)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/resolve", http.StatusOK, s.endpointResolveDocument)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIv1, http.MethodDelete, "/document", http.StatusNoContent, s.endpointDeleteDocumentByKey)

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
