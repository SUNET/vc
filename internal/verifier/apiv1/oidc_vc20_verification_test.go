package apiv1

import (
	"context"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"

	"github.com/stretchr/testify/require"
)

const unsignedW3CPresentation = `{
	"@context": "https://www.w3.org/ns/credentials/v2",
	"type": ["VerifiablePresentation"],
	"holder": "did:example:holder",
	"verifiableCredential": [{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject", "name": "Alice"}
	}]
}`

// TestVerifyVC20ForOIDCRefusesAnUnsignedDocument: the OIDC direct-post path
// verifies nothing for any format, and that is not a licence to add another
// unverified one. Making W3C usable there means an arbitrary JSON-LD
// document would otherwise have its credentialSubject mapped into the
// session, with nothing checking who signed it.
//
// A document with no proof at all is the cheapest thing an attacker posts,
// so it is the case worth pinning.
func TestVerifyVC20ForOIDCRefusesAnUnsignedDocument(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	session := &cache.AuthorizationContext{
		Nonce:    "session-nonce",
		ClientID: "x509_san_dns:verifier.example.com",
		Scopes:   []string{"pid"},
	}

	err := client.verifyVC20ForOIDC(t.Context(), session, unsignedW3CPresentation)
	require.Error(t, err, "an unsigned presentation must not reach claim extraction")
}

// TestVerifyVC20ForOIDCNeedsASession keeps the guard from being skippable by
// arriving without one.
func TestVerifyVC20ForOIDCNeedsASession(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	require.Error(t, client.verifyVC20ForOIDC(t.Context(), nil, unsignedW3CPresentation))
}

// TestVerifyVC20ForOIDCNeedsAKeyResolvingEvaluator: without one there is no
// way to check a proof, and "cannot verify" has to mean refuse.
func TestVerifyVC20ForOIDCNeedsAKeyResolvingEvaluator(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = evaluatorWithoutKeyResolution{}

	err := client.verifyVC20ForOIDC(t.Context(), &cache.AuthorizationContext{Nonce: "n", ClientID: "c"}, unsignedW3CPresentation)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key-resolving")
}

// TestVerifyVC20ForOIDCLetsANonW3CResponseThrough: a DCQL response is a JSON
// object too, so a detector that only asks "does this look like JSON" calls
// the ENVELOPE a W3C credential - and a conformant direct-post carrying
// SD-JWTs would fail W3C verification on the wrapper without its contents
// ever being looked at.
func TestVerifyVC20ForOIDCLetsANonW3CResponseThrough(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	session := &cache.AuthorizationContext{Nonce: "n", ClientID: "c", Scopes: []string{"pid"}}

	for name, token := range map[string]string{
		"a DCQL envelope of SD-JWTs": `{"pid": ["eyJhbGciOiJFUzI1NiJ9.x.y~"]}`,
		"a bare SD-JWT":              "eyJhbGciOiJFUzI1NiJ9.x.y~",
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, client.verifyVC20ForOIDC(t.Context(), session, token),
				"a response carrying no W3C document is not this guard's business")
		})
	}
}

// evaluatorWithoutKeyResolution is a TrustEvaluator that does NOT implement
// trust.KeyResolver, which AllowAllEvaluator does.
type evaluatorWithoutKeyResolution struct{}

func (evaluatorWithoutKeyResolution) Evaluate(_ context.Context, _ *trust.EvaluationRequest) (*trustapi.TrustDecision, error) {
	return &trustapi.TrustDecision{Trusted: true}, nil
}

func (evaluatorWithoutKeyResolution) SupportsKeyType(_ trust.KeyType) bool { return true }

// TestProcessDirectPostRefusesAnUnverifiedW3CToken is the call-site half:
// the guard only matters if ProcessDirectPost installs it before extracting
// claims.
//
// An unsigned presentation posted to this endpoint must be refused. Without
// the gate it parses fine - the claims extractor reads credentialSubject
// happily - and Alice's name lands in the OIDC session.
func TestProcessDirectPostRefusesAnUnverifiedW3CToken(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	const sessionID = "session-w3c-unverified"
	require.NoError(t, client.cacheService.AuthContext.Create(ctx, &cache.AuthorizationContext{
		SessionID:   sessionID,
		Status:      cache.SessionStatusPending,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
		ClientID:    "test-client",
		RedirectURI: "https://client.example.com/callback",
		Scopes:      []string{"openid", "pid"},
		State:       sessionID,
		Nonce:       "session-nonce",
	}))

	resp, err := client.ProcessDirectPost(ctx, &DirectPostRequest{
		State:   sessionID,
		VPToken: unsignedW3CPresentation,
	})
	require.Error(t, err, "an unsigned W3C presentation must not be accepted")
	require.ErrorIs(t, err, ErrInvalidVP)
	require.Nil(t, resp)
}

// TestVerifyVC20ForOIDCRefusesMoreThanOneCredential: VerifyAndExtract
// verifies the FIRST embedded credential, while the claim extraction that
// follows merges every one of them - so a presentation with a valid first
// credential and an unverified second would have the second's claims
// injected into the OIDC session.
func TestVerifyVC20ForOIDCRefusesMoreThanOneCredential(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	const credential = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject", "name": "Alice"}
	}`
	twoCredentials := `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"verifiableCredential": [` + credential + `, ` + credential + `]
	}`

	err := client.verifyVC20ForOIDC(t.Context(), &cache.AuthorizationContext{
		Nonce: "n", ClientID: "c", Scopes: []string{"pid"},
	}, twoCredentials)
	require.Error(t, err)
	require.Contains(t, err.Error(), "only the first is verified")
}

// TestOIDCScopeFor covers how a returned document is attributed to a scope,
// which is what decides whose type constraint applies to it.
func TestOIDCScopeFor(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	session := &cache.AuthorizationContext{
		Scopes: []string{"openid", "pid", "ehic"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
			{ID: "eudi_pid", Format: openid4vp.FormatLdpVCDCQL, Meta: openid4vp.MetaQuery{TypeValues: [][]string{{"https://example.org/Pid"}}}},
			{ID: "eudi_ehic", Format: openid4vp.FormatLdpVCDCQL, Meta: openid4vp.MetaQuery{TypeValues: [][]string{{"https://example.org/Ehic"}}}},
		}},
		ScopeQueryIDs: map[string]string{"pid": "eudi_pid", "ehic": "eudi_ehic"},
	}

	require.Equal(t, "pid", client.oidcScopeFor(session, "eudi_pid"))
	require.Equal(t, "ehic", client.oidcScopeFor(session, "eudi_ehic"))

	// A bare document with more than one credential scope in play cannot be
	// attributed, and the caller refuses rather than picking one.
	require.Empty(t, client.oidcScopeFor(session, ""))

	// A key naming nothing in the request is not attributed either.
	require.Empty(t, client.oidcScopeFor(session, "something_else"))

	// With exactly one credential scope, a bare document is unambiguous.
	single := &cache.AuthorizationContext{
		Scopes: []string{"openid", "pid"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
			{ID: "eudi_pid", Format: openid4vp.FormatLdpVCDCQL, Meta: openid4vp.MetaQuery{TypeValues: [][]string{{"https://example.org/Pid"}}}},
		}},
		ScopeQueryIDs: map[string]string{"pid": "eudi_pid"},
	}
	require.Equal(t, "pid", client.oidcScopeFor(single, ""))
}

// TestCheckVC20AnswersTheRequest: MatchTypeValues is satisfied by an EMPTY
// TypeValues, and an mdoc or SD-JWT query has none - so without a format
// check a signed W3C credential answers a query that asked for something
// else entirely, and its claims are accepted by the OIDC flow.
func TestCheckVC20AnswersTheRequest(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	sessionWith := func(query openid4vp.CredentialQuery) *cache.AuthorizationContext {
		return &cache.AuthorizationContext{
			Scopes:        []string{"openid", "pid"},
			DCQLQuery:     &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{query}},
			ScopeQueryIDs: map[string]string{"pid": query.ID},
		}
	}

	const pidType = "https://example.org/Pid"
	w3cQuery := openid4vp.CredentialQuery{
		ID: "eudi_pid", Format: openid4vp.FormatLdpVCDCQL,
		Meta: openid4vp.MetaQuery{TypeValues: [][]string{{pidType}}},
	}

	t.Run("a matching W3C query is satisfied", func(t *testing.T) {
		require.NoError(t, client.checkVC20AnswersTheRequest(sessionWith(w3cQuery), "pid", []string{pidType}))
	})

	t.Run("a W3C query the credential does not satisfy", func(t *testing.T) {
		err := client.checkVC20AnswersTheRequest(sessionWith(w3cQuery), "pid", []string{"https://example.org/SomethingElse"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not have a type the request asked for")
	})

	for name, format := range map[string]string{
		"an mdoc query":   openid4vp.FormatMsoMdoc,
		"an SD-JWT query": openid4vp.FormatSDJWTVC,
	} {
		t.Run(name+" is not answered by a W3C credential", func(t *testing.T) {
			query := openid4vp.CredentialQuery{ID: "eudi_pid", Format: format,
				Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}, DoctypeValue: "eu.europa.ec.eudi.pid.1"}}
			err := client.checkVC20AnswersTheRequest(sessionWith(query), "pid", []string{pidType})
			require.Error(t, err)
			require.Contains(t, err.Error(), "does not answer it",
				"an empty TypeValues must not be read as an unconstrained match")
		})
	}

	t.Run("an unnameable scope is refused", func(t *testing.T) {
		require.Error(t, client.checkVC20AnswersTheRequest(sessionWith(w3cQuery), "", []string{pidType}))
	})

	t.Run("a scope whose query cannot be recovered is refused", func(t *testing.T) {
		require.Error(t, client.checkVC20AnswersTheRequest(&cache.AuthorizationContext{Scopes: []string{"pid"}}, "pid", []string{pidType}))
	})
}
