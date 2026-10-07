package apiv1

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/auth_providers/oidcrp"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// policyMockOP is the smallest OIDC Provider that a real oidcrp.Service will
// complete a code exchange against: discovery, JWKS, and a token endpoint that
// signs an ID token carrying whatever the test wants asserted.
//
// UserInfo returns only sub. The callback merges UserInfo over the ID token
// claims, and anything identity-shaped there (given_name and friends) would
// send the handler on to identity-mapping resolution, which needs a database.
// The gate under test sits before that.
type policyMockOP struct {
	server     *httptest.Server
	signingKey *rsa.PrivateKey
	keyID      string
	clientID   string
	issuerURL  string

	// asserts is merged into the ID token: what the OP says about the user.
	asserts map[string]any
}

func newPolicyMockOP(t *testing.T) *policyMockOP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	op := &policyMockOP{signingKey: key, keyID: "policy-test-key", clientID: "policy-test-client"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                op.issuerURL,
			"authorization_endpoint":                op.issuerURL + "/authorize",
			"token_endpoint":                        op.issuerURL + "/token",
			"userinfo_endpoint":                     op.issuerURL + "/userinfo",
			"jwks_uri":                              op.issuerURL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &op.signingKey.PublicKey, KeyID: op.keyID, Algorithm: string(jose.RS256), Use: "sig",
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		// The nonce is carried in the code, as the other OIDC tests do it.
		nonce := ""
		if parts := strings.SplitN(r.FormValue("code"), "|", 2); len(parts) == 2 {
			nonce = parts[1]
		}
		writeJSON(w, map[string]any{
			"access_token": "policy-test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     op.signIDToken(nonce),
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"sub": "policy-test-user"})
	})

	op.server = httptest.NewServer(mux)
	op.issuerURL = op.server.URL
	t.Cleanup(op.server.Close)

	return op
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (op *policyMockOP) signIDToken(nonce string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": op.issuerURL,
		"sub": "policy-test-user",
		"aud": op.clientID,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	maps.Copy(claims, op.asserts)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = op.keyID
	raw, err := token.SignedString(op.signingKey)
	if err != nil {
		panic(err)
	}

	return raw
}

// TestOIDCRPCallbackAppliesIssuancePolicy exercises the policy gate through
// the handler that owns it.
//
// The point of going via OIDCRPCallback rather than building a PolicyEngine
// and evaluating it: a test that constructs its own engine passes whether or
// not the handler still consults one, so deleting the gate from the callback
// would leave it green. Here the assertions are the handler's own return
// values, against claims a real mock OP signed and the real oidcrp callback
// verified, so removing or bypassing the gate fails this.
//
// The allowed case is recognised by where it fails instead: past the gate, the
// standalone path needs an identifier this mock OP does not supply, and says
// so. That error is the evidence the policy let the request through - and it
// is asserted explicitly, so the test cannot pass by the handler failing
// somewhere earlier for an unrelated reason.
func TestOIDCRPCallbackAppliesIssuancePolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		asserts   map[string]any
		wantDeny  bool
		wantAfter string
	}{
		{
			name:      "the OP asserts the acr the policy requires",
			asserts:   map[string]any{"acr": "loa3"},
			wantAfter: "requires an identifier",
		},
		{
			name:     "the OP asserts a weaker acr",
			asserts:  map[string]any{"acr": "loa1"},
			wantDeny: true,
		},
		{
			// Absent is not the same as present-and-wrong: an unset
			// dimension must not read as a wildcard.
			name:     "the OP asserts no acr at all",
			asserts:  nil,
			wantDeny: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, service := newPolicyGateTestClient(t, tc.asserts)

			ctx := t.Context()
			authReq, err := service.InitiateAuth(ctx, "pid", nil, nil)
			require.NoError(t, err)

			session, err := service.GetSession(ctx, authReq.State)
			require.NoError(t, err)

			_, err = client.OIDCRPCallback(ctx, &OIDCRPCallbackRequest{
				Code:  "policy-test-code|" + session.Nonce,
				State: authReq.State,
			}, service)

			require.Error(t, err, "this flow never reaches a successful issuance in-process")
			if tc.wantDeny {
				require.Contains(t, err.Error(), "credential issuance denied",
					"the callback must refuse before doing anything else with these claims")

				return
			}
			require.NotContains(t, err.Error(), "credential issuance denied",
				"the policy was satisfied, so the gate must not have refused")
			require.Contains(t, err.Error(), tc.wantAfter,
				"the callback must have carried on past the gate to the step that needs an identifier")
		})
	}
}

// TestOIDCRPCallbackDeletesSessionOnPolicyDenial pins the cleanup that the
// denial path used to skip.
//
// The deferred cleanup keys off the function's error result, and the denial
// branch returned through a local `policyErr` — so the outer error stayed nil,
// the cleanup did not run, and a session whose code had already been redeemed
// sat in the cache until its TTL. The request was refused and the state that
// carried it was kept, which is the wrong half of the transaction to preserve.
//
// Asserted through the handler rather than by inspecting the branch, so it
// also covers the other error returns that use their own local variables.
func TestOIDCRPCallbackDeletesSessionOnPolicyDenial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		asserts map[string]any
	}{
		{"policy denies", map[string]any{"acr": "loa1"}},
		{"policy passes but a later step fails", map[string]any{"acr": "loa3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, service := newPolicyGateTestClient(t, tc.asserts)

			ctx := t.Context()
			authReq, err := service.InitiateAuth(ctx, "pid", nil, nil)
			require.NoError(t, err)

			session, err := service.GetSession(ctx, authReq.State)
			require.NoError(t, err)

			_, err = client.OIDCRPCallback(ctx, &OIDCRPCallbackRequest{
				Code:  "policy-test-code|" + session.Nonce,
				State: authReq.State,
			}, service)
			require.Error(t, err)

			_, err = service.GetSession(ctx, authReq.State)
			require.Error(t, err, "a failed callback must not leave its OIDC session behind")
		})
	}
}

// newPolicyGateTestClient wires a Client with only what the callback needs to
// reach the policy gate, a real oidcrp.Service, and a scope configured with a
// policy that requires acr loa3.
func newPolicyGateTestClient(t *testing.T, opAsserts map[string]any) (*Client, *oidcrp.Service) {
	t.Helper()
	ctx := t.Context()

	log, err := logger.New("policy-gate-test", "", false)
	require.NoError(t, err)

	tracer, err := trace.NewForTesting(ctx, "policy-gate-test", log)
	require.NoError(t, err)

	op := newPolicyMockOP(t)
	op.asserts = opAsserts

	sessionCache := pkgcache.NewMemoryCache[*oidcrp.Session](5 * time.Minute)
	t.Cleanup(sessionCache.Stop)

	service, err := oidcrp.New(ctx, &model.OIDCRP{
		Enable: true,
		Registration: &model.OIDCRPRegistrationConfig{
			Preconfigured: &model.OIDCRPPreconfiguredConfig{
				Enable:       true,
				ClientID:     op.clientID,
				ClientSecret: "policy-test-secret",
			},
			Dynamic: &model.OIDCRPDynamicRegistrationConfig{Enable: false},
		},
		IssuerURL:       op.issuerURL,
		RedirectURI:     op.issuerURL + "/callback",
		Scopes:          []string{"openid"},
		SessionDuration: 300,
	}, sessionCache, nil, nil, log)
	require.NoError(t, err)
	require.NotNil(t, service)

	client := &Client{
		log:    log,
		tracer: tracer,
		cfg: &model.Cfg{
			Common: &model.Common{},
			APIGW: &model.APIGW{
				DataSources: model.DataSources{
					Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
						"pid": {
							AuthProvider: model.AuthProviderOIDC,
							IssuancePolicy: &model.IssuancePolicy{
								Rules:         []string{"(credential (scope pid)(acr loa3))"},
								QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
							},
						},
					}},
				},
			},
		},
	}

	return client, service
}

// TestOIDCRPCallbackPolicyIgnoresDerivedClaims: the policy gate must read
// what the OP ASSERTED, and derivations are computed locally afterwards.
//
// The two met through aliasing rather than by design. With no attribute
// mapper configured, newCallbackClaims sets cc.identity = raw - the very
// map authResp.Claims points at - and MergeNestedClaims then writes the
// configured derivations into it. The policy snapshot was taken at the
// point of evaluation, by which time those derived values were simply part
// of the claims, indistinguishable from the OP's own.
//
// So a deployment could satisfy "(acr loa3)" with an acr it computed for
// itself out of a claim the OP never vouched for - here, lowercasing a
// loa_hint. The OP asserts no acr at all in this test; the only acr that
// could reach the policy is the derived one.
func TestOIDCRPCallbackPolicyIgnoresDerivedClaims(t *testing.T) {
	client, service := newPolicyGateTestClient(t, map[string]any{"loa_hint": "LOA3"})

	// An ASSERTION scope, which is the shape where the two paths actually
	// meet: derivations run in this callback only for assertion-backed
	// credentials (datastore and external_api derive later, against the
	// fetched document), and LookupScopePolicyConfig reads assertion scopes
	// too. A datastore scope never executes the derivation branch at all,
	// so a fixture built on one tests nothing here.
	client.cfg.APIGW.DataSources = model.DataSources{
		Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
			"pid": {
				AuthProvider: model.AuthProviderOIDC,
				IssuancePolicy: &model.IssuancePolicy{
					Rules:         []string{"(credential (scope pid)(acr loa3))"},
					QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
				},
				// Manufactures exactly the claim the policy gates on.
				Derivations: []primitives.Derivation{{
					Lowercase: &primitives.LowercaseArgs{Input: "loa_hint", Output: "acr"},
				}},
			},
		}},
	}

	ctx := t.Context()
	authReq, err := service.InitiateAuth(ctx, "pid", nil, nil)
	require.NoError(t, err)
	session, err := service.GetSession(ctx, authReq.State)
	require.NoError(t, err)

	_, err = client.OIDCRPCallback(ctx, &OIDCRPCallbackRequest{
		Code:  "policy-test-code|" + session.Nonce,
		State: authReq.State,
	}, service)

	require.Error(t, err)
	require.Contains(t, err.Error(), "credential issuance denied",
		"a locally derived acr must not satisfy a policy that gates on the OP's acr")
}
