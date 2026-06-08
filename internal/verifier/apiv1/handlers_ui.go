package apiv1

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// UICredentialInfo is a sanitized view of a credential for the UI.
type UICredentialInfo struct {
	VCT        string                         `json:"vct"`
	Attributes map[string]map[string][]string `json:"attributes"`
}

// UIPreset is a verification preset served to the UI.
type UIPreset struct {
	Label       string               `json:"label"`
	Credentials []UIPresetCredential `json:"credentials"`
}

// UIPresetCredential is a credential query within a preset.
type UIPresetCredential struct {
	ID          string                      `json:"id"`
	Format      string                      `json:"format"`
	Meta        UIPresetMeta                `json:"meta"`
	Claims      []UIPresetClaim             `json:"claims,omitempty"`
	Validations []openid4vp.ClaimValidation `json:"validations,omitempty"`
}

// UIPresetMeta holds credential metadata for the preset.
type UIPresetMeta struct {
	VCTValues []string `json:"vct_values"`
}

// UIPresetClaim is a claim path within a preset credential.
type UIPresetClaim struct {
	Path []string `json:"path"`
}

type UIMetadataReply struct {
	Credentials      map[string]*UICredentialInfo `json:"credentials"`
	SupportedWallets map[string]string            `json:"supported_wallets"`
	Presets          map[string]*UIPreset         `json:"presets,omitempty"`
}

func (c *Client) UIMetadata(ctx context.Context) (*UIMetadataReply, error) {
	reply := &UIMetadataReply{
		Credentials:      make(map[string]*UICredentialInfo),
		SupportedWallets: c.cfg.Verifier.SupportedWallets,
	}

	for scope, constructor := range c.cfg.Common.CredentialMetadata {
		info := &UICredentialInfo{
			Attributes: constructor.GetAttributes(),
		}
		if v := constructor.GetVCTURL(); v != "" {
			info.VCT = v
		} else if vctm := constructor.GetVCTM(); vctm != nil {
			info.VCT = vctm.VCT
		}
		reply.Credentials[scope] = info
	}

	// Convert config presets to UI presets, resolving VCT values from credential metadata
	if len(c.cfg.Verifier.Presets) > 0 {
		reply.Presets = make(map[string]*UIPreset, len(c.cfg.Verifier.Presets))
		presetLabels := make([]string, 0, len(c.cfg.Verifier.Presets))
		for label := range c.cfg.Verifier.Presets {
			presetLabels = append(presetLabels, label)
		}
		sort.Strings(presetLabels)
		for _, label := range presetLabels {
			preset := c.cfg.Verifier.Presets[label]
			uiPreset := &UIPreset{
				Label:       label,
				Credentials: make([]UIPresetCredential, 0, len(preset)),
			}
			scopeKeys := make([]string, 0, len(preset))
			for scope := range preset {
				scopeKeys = append(scopeKeys, scope)
			}
			sort.Strings(scopeKeys)
			for _, scope := range scopeKeys {
				scopeCfg := preset[scope]
				meta := c.cfg.Common.CredentialMetadata[scope]
				if meta == nil {
					return nil, fmt.Errorf("preset %q references scope %q which has no entry in credential_metadata", label, scope)
				}

				uiCred := UIPresetCredential{
					ID:   scope,
					Meta: UIPresetMeta{VCTValues: []string{}},
				}

				// Resolve format and VCT from credential_metadata
				if meta != nil {
					uiCred.Format = meta.Format
					if v := meta.GetVCTURL(); v != "" {
						uiCred.Meta.VCTValues = []string{v}
					} else if vctm := meta.GetVCTM(); vctm != nil {
						uiCred.Meta.VCTValues = []string{vctm.VCT}
					}
				}

				// scopeCfg may be nil (scope with no overrides)
				var claims []model.VerificationPresetClaim
				var excludeSet map[string]bool
				if scopeCfg != nil {
					claims = scopeCfg.Claims
					excludeSet = make(map[string]bool, len(scopeCfg.ExcludeClaims))
					for _, ex := range scopeCfg.ExcludeClaims {
						excludeSet[claimPathKey(ex.Path)] = true
					}
					// Attach validations to this credential
					uiCred.Validations = scopeCfg.Validations
				}

				// Resolve claims: use explicit claims, or fall back to VCTM claims
				if len(claims) == 0 && meta != nil {
					if vctm := meta.GetVCTM(); vctm != nil {
						// First pass: collect all valid leaf paths
						var allPaths [][]string
						for _, vc := range vctm.Claims {
							path := make([]string, 0, len(vc.Path))
							isLeaf := true
							for _, seg := range vc.Path {
								if seg == nil {
									isLeaf = false
									break
								}
								path = append(path, *seg)
							}
							if isLeaf && len(path) > 0 && !jwtRegisteredClaim(path[0]) {
								allPaths = append(allPaths, path)
							}
						}
						// Build set of parent prefixes: for each path, mark all its proper prefixes
						parentSet := make(map[string]bool)
						for _, p := range allPaths {
							for i := 1; i < len(p); i++ {
								parentSet[claimPathKey(p[:i])] = true
							}
						}
						// Second pass: only include non-parent claims
						for _, path := range allPaths {
							if !parentSet[claimPathKey(path)] {
								claims = append(claims, model.VerificationPresetClaim{Path: path})
							}
						}
					}
				}

				for _, claim := range claims {
					if !excludeSet[claimPathKey(claim.Path)] {
						uiCred.Claims = append(uiCred.Claims, UIPresetClaim{Path: claim.Path})
					}
				}
				uiPreset.Credentials = append(uiPreset.Credentials, uiCred)
			}
			reply.Presets[label] = uiPreset
		}
	}

	return reply, nil
}

type UIInteractionRequest struct {
	DCQLQuery   *openid4vp.DCQL                        `json:"dcql_query" validate:"required"`
	Validations map[string][]openid4vp.ClaimValidation `json:"validations,omitempty" validate:"omitempty,dive,dive"`

	// SessionID from http server endpoint
	SessionID string `json:"-"`
}

type UIInteractionReply struct {
	AuthorizationRequest string `json:"authorization_request"`
	QRCode               string `json:"qr_code"`
}

// UIInteraction handles front-end interactions, replying with an Authorization Request that contains a Request URI and DCQL query, the latter for UI to show.
func (c *Client) UIInteraction(ctx context.Context, req *UIInteractionRequest) (*UIInteractionReply, error) {
	c.log.Debug("uiInteraction", "dcql_query", req.DCQLQuery)

	nonce := uuid.NewString()
	state := uuid.NewString()
	requestObjectID := uuid.NewString()

	// Use session ID from request if provided, otherwise generate new one
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = uuid.NewString()
	}

	// Collect all credential IDs from DCQL query
	scopes := make([]string, 0, len(req.DCQLQuery.Credentials))
	for _, credential := range req.DCQLQuery.Credentials {
		scopes = append(scopes, credential.ID)
	}

	host, err := helpers.HostFromURL(c.cfg.Verifier.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host from PublicURL: %w", err)
	}

	authorizationContext := &cache.AuthorizationContext{
		SessionID:           sessionID,
		Scopes:              scopes,
		Code:                "",
		RequestURI:          "",
		WalletURI:           "",
		Forfeited:           false,
		State:               state,
		ClientID:            fmt.Sprintf("x509_san_dns:%s", host),
		ExpiresAt:           0,
		CodeChallenge:       "",
		CodeChallengeMethod: "",
		Consent:             false,
		AuthenticSource:     "",
		// Identity and Token are nil until wallet presents credentials
		Nonce:                    nonce,
		EphemeralEncryptionKeyID: uuid.NewString(),
		VerifierResponseCode:     "",
		RequestObjectID:          requestObjectID,
		Validations:              req.Validations,
	}

	_, ephemeralPublicJWK, err := c.openid4vp.EphemeralKeyCache.GenerateAndStore(authorizationContext.EphemeralEncryptionKeyID)
	if err != nil {
		return nil, err
	}

	responseURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "verification", "direct_post")
	if err != nil {
		return nil, fmt.Errorf("failed to construct response URI: %w", err)
	}

	requestObject := &openid4vp.RequestObject{
		ResponseURI:  responseURI,
		AUD:          "https://self-issued.me/v2",
		ISS:          host,
		ClientID:     authorizationContext.ClientID,
		ResponseType: "vp_token",
		ResponseMode: "direct_post.jwt",
		State:        authorizationContext.State,
		Nonce:        authorizationContext.Nonce,
		ClientMetadata: &openid4vp.ClientMetadata{
			VPFormatsSupported: c.cfg.Verifier.PreferredVPFormats,
			JWKS: &openid4vp.Keys{
				Keys: []jwk.Key{ephemeralPublicJWK},
			},
			AuthorizationSignedResponseALG:    "",
			AuthorizationEncryptedResponseALG: "ECDH-ES",
			AuthorizationEncryptedResponseENC: "A256GCM",
		},
		IAT:              time.Now().UTC().Unix(),
		RedirectURI:      "",
		Scope:            "",
		DCQLQuery:        req.DCQLQuery,
		RequestURIMethod: "",
		TransactionData:  []openid4vp.TransactionData{},
		VerifierInfo:     []openid4vp.VerifierInfo{},
	}

	if err := c.cacheService.AuthContext.Save(ctx, authorizationContext); err != nil {
		return nil, err
	}

	c.openid4vp.RequestObjectCache.Set(authorizationContext.RequestObjectID, requestObject)

	reply := &UIInteractionReply{}

	reply.AuthorizationRequest, err = requestObject.CreateAuthorizationRequestURI(ctx, c.cfg.Verifier.PublicURL, requestObjectID)
	if err != nil {
		return nil, err
	}

	reply.QRCode, err = openid4vp.GenerateQRV2(ctx, reply.AuthorizationRequest)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// claimPathKey returns a string key for a claim path for use in exclusion sets.
// Uses a null byte separator to avoid ambiguity when segments contain dots.
func claimPathKey(path []string) string {
	return strings.Join(path, "\x00")
}

// jwtRegisteredClaims are standard JWT/SD-JWT claims that should not appear in DCQL queries.
var jwtRegisteredClaims = map[string]bool{
	"iss":    true,
	"sub":    true,
	"iat":    true,
	"nbf":    true,
	"exp":    true,
	"cnf":    true,
	"vct":    true,
	"status": true,
}

// jwtRegisteredClaim reports whether name is a standard JWT/SD-JWT claim.
func jwtRegisteredClaim(name string) bool {
	return jwtRegisteredClaims[name]
}
