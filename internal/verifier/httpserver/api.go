package httpserver

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
	"vc/internal/verifier/apiv1"
	"vc/pkg/jose"
	"vc/pkg/oauth2"
)

type Apiv1 interface {
	// oauth2
	OAuthMetadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, error)

	// misc
	Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error)

	// Verification
	VerificationRequestObject(ctx context.Context, req *apiv1.VerificationRequestObjectRequest) (string, error)
	VerificationDirectPost(ctx context.Context, req *apiv1.VerificationDirectPostRequest) (*apiv1.VerificationDirectPostResponse, error)
	VerificationCallback(ctx context.Context, req *apiv1.VerificationCallbackRequest) (*apiv1.VerificationCallbackResponse, error)

	// UI
	UIInteraction(ctx context.Context, req *apiv1.UIInteractionRequest) (*apiv1.UIInteractionReply, error)
	UIMetadata(ctx context.Context) (*apiv1.UIMetadataReply, error)

	// OIDC Provider
	GetDiscoveryMetadata(ctx context.Context) (*apiv1.DiscoveryMetadata, error)
	GetJWKS(ctx context.Context) (*jose.JWKS, error)
	Authorize(ctx context.Context, req *apiv1.AuthorizeRequest) (*apiv1.AuthorizeResponse, error)
	Token(ctx context.Context, req *apiv1.TokenRequest) (*apiv1.TokenResponse, error)
	GetUserInfo(ctx context.Context, req *apiv1.UserInfoRequest) (apiv1.UserInfoResponse, error)

	// OpenID4VP
	GetOIDCRequestObject(ctx context.Context, req *apiv1.GetRequestObjectRequest) (*apiv1.GetRequestObjectResponse, error)
	ProcessDirectPost(ctx context.Context, req *apiv1.DirectPostRequest) (*apiv1.DirectPostResponse, error)
	ProcessCallback(ctx context.Context, req *apiv1.CallbackRequest) (*apiv1.CallbackResponse, error)
	GetQRCode(ctx context.Context, req *apiv1.GetQRCodeRequest) (*apiv1.GetQRCodeResponse, error)
	PollSession(ctx context.Context, req *apiv1.PollSessionRequest) (*apiv1.PollSessionResponse, error)

	// Dynamic Client Registration (RFC 7591/7592)
	RegisterClient(ctx context.Context, req *apiv1.ClientRegistrationRequest) (*apiv1.ClientRegistrationResponse, error)
	GetClientInformation(ctx context.Context, clientID string, registrationAccessToken string) (*apiv1.ClientInformationResponse, error)
	UpdateClient(ctx context.Context, clientID string, registrationAccessToken string, req *apiv1.ClientRegistrationRequest) (*apiv1.ClientRegistrationResponse, error)
	DeleteClient(ctx context.Context, clientID string, registrationAccessToken string) error

	// Session/Credential Display
	UpdateSessionPreference(ctx context.Context, req *apiv1.UpdateSessionPreferenceRequest) (*apiv1.UpdateSessionPreferenceResponse, error)
	ConfirmCredentialDisplay(ctx context.Context, sessionID string, req *apiv1.ConfirmCredentialDisplayRequest) (*apiv1.ConfirmCredentialDisplayResponse, error)
	GetCredentialDisplayData(ctx context.Context, req *apiv1.GetCredentialDisplayDataRequest) (*apiv1.GetCredentialDisplayDataResponse, error)
}
