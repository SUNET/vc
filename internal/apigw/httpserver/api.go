package httpserver

import (
	"context"
	"encoding/json"
	"vc/internal/apigw/apiv1"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
	"vc/pkg/sdjwtvc"
	"vc/pkg/vcclient"
)

// Apiv1 interface
type Apiv1 interface {
	// datastore endpoints
	Upload(ctx context.Context, req *vcclient.UploadRequest) error
	Notification(ctx context.Context, req *vcclient.NotificationRequest) (*vcclient.NotificationReply, error)
	AddDocumentIdentity(ctx context.Context, req *apiv1.AddDocumentIdentityRequest) error
	DeleteDocumentIdentity(ctx context.Context, req *apiv1.DeleteDocumentIdentityRequest) error
	IdentityMapping(ctx context.Context, reg *apiv1.IdentityMappingRequest) (*apiv1.IdentityMappingReply, error)
	GetDocument(ctx context.Context, req *apiv1.GetDocumentRequest) (*apiv1.GetDocumentReply, error)
	DocumentList(ctx context.Context, req *apiv1.DocumentListRequest) (*apiv1.DocumentListReply, error)
	DeleteDocument(ctx context.Context, req *apiv1.DeleteDocumentRequest) error
	GetDocumentCollectID(ctx context.Context, req *apiv1.GetDocumentCollectIDRequest) (*apiv1.GetDocumentCollectIDReply, error)
	RevokeDocument(ctx context.Context, req *apiv1.RevokeDocumentRequest) error
	AddConsent(ctx context.Context, req *apiv1.AddConsentRequest) error
	GetConsent(ctx context.Context, req *apiv1.GetConsentRequest) (*model.Consent, error)

	// datastore endpoints - disabled in production
	SearchDocuments(ctx context.Context, req *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, error)
	AddPIDUser(ctx context.Context, req *vcclient.AddPIDRequest) error
	LoginPIDUser(ctx context.Context, req *vcclient.LoginPIDUserRequest) error
	UserAuthenticSourceLookup(ctx context.Context, req *vcclient.UserAuthenticSourceLookupRequest) (*vcclient.UserAuthenticSourceLookupReply, error)
	UserLookup(ctx context.Context, req *vcclient.UserLookupRequest) (*vcclient.UserLookupReply, error)

	// OpenID4VCI endpoints
	VCINonce(ctx context.Context) (*openid4vci.NonceResponse, error)
	VCICredential(ctx context.Context, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error)
	VCICredentialOfferURI(ctx context.Context, req *openid4vci.CredentialOfferURIRequest) (*openid4vci.CredentialOfferParameters, error)
	VCIDeferredCredential(ctx context.Context, req *openid4vci.DeferredCredentialRequest) (*openid4vci.CredentialResponse, error)
	VCINotification(ctx context.Context, req *openid4vci.NotificationRequest) error
	VCIMetadata(ctx context.Context) (*openid4vci.CredentialIssuerMetadataParameters, error)

	OAuthPar(ctx context.Context, req *openid4vci.PARRequest) (*openid4vci.ParResponse, error)
	OAuthAuthorize(ctx context.Context, req *openid4vci.AuthorizeRequest) (*openid4vci.AuthorizationResponse, error)
	OAuthAuthorizationConsent(ctx context.Context, req *apiv1.OauthAuthorizationConsentRequest) (*apiv1.OAuthAuthorizationConsentResponse, error)
	OAuthAuthorizationConsentCallback(ctx context.Context, req *apiv1.OauthAuthorizationConsentCallbackRequest) (*apiv1.OAuthAuthorizationConsentCallbackResponse, error)
	OAuthToken(ctx context.Context, req *openid4vci.TokenRequest) (*openid4vci.TokenResponse, error)
	OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error)
	JWKS(ctx context.Context) (*apiv1.JWKSResponse, error)
	SDJWTVCIssuerMetadata(ctx context.Context) (*apiv1.SDJWTVCIssuerMetadataResponse, error)

	//Revoke(ctx context.Context, req *apiv1.RevokeRequest) (*apiv1.RevokeReply, error)

	VerificationRequestObject(ctx context.Context, req *apiv1.VerificationRequestObjectRequest) (string, error)
	VerificationDirectPost(ctx context.Context, req *apiv1.VerificationDirectPostRequest) (*apiv1.VerificationDirectPostResponse, error)

	// UI Credential Offer endpoints
	UICredentialOffers(ctx context.Context) (*apiv1.CredentialOfferLookupMetadata, error)
	UICreateCredentialOffer(ctx context.Context, req *apiv1.UICredentialOfferRequest) (*apiv1.CredentialOfferReply, error)

	GetVCTMFromScope(ctx context.Context, req *apiv1.GetVCTMFromScopeRequest) (*sdjwtvc.VCTM, error)
	SVGTemplateReply(ctx context.Context, req *apiv1.SVGTemplateRequest) (*vcclient.SVGTemplateReply, error)
	TypeMetadata(ctx context.Context, req *apiv1.TypeMetadataRequest) (json.RawMessage, error)

	// OIDC RP endpoints
	OIDCRPInitiate(ctx context.Context, req *apiv1.OIDCRPInitiateRequest, oidcrpService any) (*apiv1.OIDCRPInitiateResponse, error)
	OIDCRPCallback(ctx context.Context, req *apiv1.OIDCRPCallbackRequest, oidcrpService any) (*apiv1.OIDCRPCallbackResponse, error)

	// VCI integration for external auth (SAML/OIDC)
	StoreVCIDocuments(ctx context.Context, sessionID string, docs map[string]*model.CompleteDocument) error
	HasVCIDocuments(ctx context.Context, sessionID string) bool

	// misc endpoints
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
