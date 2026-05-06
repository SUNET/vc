package httpserver

import (
	"context"
	"encoding/json"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/vcclient"
)

// Apiv1 interface
type Apiv1 interface {
	// datastore endpoints
	DatastoreUpload(ctx context.Context, req *vcclient.UploadRequest) error
	DatastoreAddIdentity(ctx context.Context, req *apiv1.DatastoreAddIdentityRequest) error
	DatastoreDeleteIdentity(ctx context.Context, req *apiv1.DatastoreDeleteIdentityRequest) error
	DatastoreGet(ctx context.Context, req *apiv1.DatastoreGetRequest) (*apiv1.DatastoreGetReply, error)
	DatastoreList(ctx context.Context, req *apiv1.DatastoreListRequest) (*apiv1.DatastoreListReply, error)
	DatastoreDelete(ctx context.Context, req *apiv1.DatastoreDeleteRequest) error
	DatastoreGetByKey(ctx context.Context, req *apiv1.DatastoreGetByKeyRequest) (*apiv1.DatastoreGetByKeyReply, error)
	DatastoreResolve(ctx context.Context, req *apiv1.DatastoreResolveRequest) (*apiv1.DatastoreResolveReply, error)
	DatastoreDeleteByKey(ctx context.Context, req *apiv1.DatastoreDeleteByKeyRequest) error

	// user endpoints
	UserAuthenticSourceLookup(ctx context.Context, req *vcclient.UserAuthenticSourceLookupRequest) (*vcclient.UserAuthenticSourceLookupReply, error)
	UserLookup(ctx context.Context, req *vcclient.UserLookupRequest) (*vcclient.UserLookupReply, error)

	// identity mapping endpoints
	IdentityMappingCreate(ctx context.Context, req *apiv1.IdentityMappingCreateRequest) (*apiv1.IdentityMappingCreateReply, error)
	IdentityMappingResolve(ctx context.Context, req *apiv1.IdentityMappingResolveRequest) (*apiv1.IdentityMappingResolveReply, error)
	IdentityMappingUpdate(ctx context.Context, req *apiv1.IdentityMappingUpdateRequest) error
	IdentityMappingDelete(ctx context.Context, req *apiv1.IdentityMappingDeleteRequest) error

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
	LookupDatastoreByIdentity(ctx context.Context, sessionID, scope, authenticSource string, claims map[string]any, dsCred *model.DatastoreScope) error
	ResolveIdentifier(ctx context.Context, authenticSource string, claims map[string]any) (string, error)

	// misc endpoints
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)
}
