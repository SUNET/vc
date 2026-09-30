package apiv1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"
	"github.com/SUNET/vc/pkg/vc20/credential"
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

// w3cOIDCFixture mints a real issuer-signed credential and gives back a
// builder for holder presentations of it, on a client whose trust evaluator
// can resolve both keys.
func w3cOIDCFixture(t *testing.T) (*Client, []byte, func(t *testing.T, nonce, domain string) string) {
	t.Helper()
	ctx := t.Context()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const degreeContext = "https://example.org/degree"
	credential.GetGlobalLoader().AddContext(degreeContext,
		`{"@context":{"UniversityDegreeCredential":"https://example.org/degree#UniversityDegreeCredential"}}`)

	issuerHandler, err := openid4vp.NewVC20Handler(
		openid4vp.WithVC20SignerConfig(&openid4vp.VC20SignerConfig{
			PrivateKey:         issuerKey,
			IssuerID:           "did:example:issuer",
			VerificationMethod: "did:example:issuer#key-1",
			Cryptosuite:        openid4vp.CryptosuiteECDSA2019,
		}),
	)
	require.NoError(t, err)

	created, err := issuerHandler.CreateCredential(ctx, &openid4vp.VC20CreateRequest{
		Types:              []string{"UniversityDegreeCredential"},
		AdditionalContexts: []string{degreeContext},
		Subject:            map[string]any{"id": "did:example:subject", "degree": "Master of Science"},
	})
	require.NoError(t, err)

	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = &staticKeyEvaluator{keys: map[string]crypto.PublicKey{
		"did:example:issuer#key-1": &issuerKey.PublicKey,
		"did:example:holder#key-1": &holderKey.PublicKey,
	}}

	present := func(t *testing.T, nonce, domain string) string {
		t.Helper()
		vp, err := openid4vp.NewVPBuilder().BuildVC20Presentation(
			[][]byte{created.CredentialJSON},
			holderKey,
			&openid4vp.VPBuildOptions{
				HolderDID:          "did:example:holder",
				VerificationMethod: "did:example:holder#key-1",
				Nonce:              nonce,
				Domain:             domain,
				Cryptosuite:        openid4vp.CryptosuiteECDSA2019,
			},
		)
		require.NoError(t, err)
		return string(vp)
	}

	return client, created.CredentialJSON, present
}

// w3cOIDCSession is a request for one W3C credential under scope "pid",
// asking for the type the fixture mints.
func w3cOIDCSession(holderBinding *bool) *cache.AuthorizationContext {
	return &cache.AuthorizationContext{
		Nonce:              "the-clients-oidc-nonce",
		RequestObjectNonce: "the-request-objects-nonce",
		ClientID:           "relying-party-oauth-client-id",
		Scopes:             []string{"openid", "pid"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "eudi_pid",
			Format: openid4vp.FormatLdpVCDCQL,
			Meta: openid4vp.MetaQuery{TypeValues: [][]string{
				{openid4vp.BaseVCTypeIRI, "https://example.org/degree#UniversityDegreeCredential"},
			}},
			RequireCryptographicHolderBinding: holderBinding,
		}}},
		ScopeQueryIDs: map[string]string{"pid": "eudi_pid"},
	}
}

func envelope(queryID, token string) string {
	body, err := json.Marshal(map[string][]string{queryID: {token}})
	if err != nil {
		panic(err)
	}
	return string(body)
}

// TestVerifyVC20ForOIDCBindsToTheRequestObjectNonce: the wallet was asked to
// put the REQUEST OBJECT's nonce in the proof - GetOIDCRequestObject
// generates it and stores it as RequestObjectNonce. session.Nonce is the
// relying party's optional OIDC nonce; it may be empty and it is generally
// something else entirely. Binding against that one rejects every valid
// presentation this path can receive.
func TestVerifyVC20ForOIDCBindsToTheRequestObjectNonce(t *testing.T) {
	client, _, present := w3cOIDCFixture(t)
	domain, err := client.cfg.Verifier.VerifierClientID(client.pkiSigningCert)
	require.NoError(t, err)

	session := w3cOIDCSession(nil)

	t.Run("bound to the request object's nonce", func(t *testing.T) {
		token := present(t, session.RequestObjectNonce, domain)
		require.NoError(t, client.verifyVC20ForOIDC(t.Context(), session, envelope("eudi_pid", token)),
			"a presentation carrying the challenge the wallet was given must verify")
	})

	t.Run("bound to the client's OIDC nonce", func(t *testing.T) {
		token := present(t, session.Nonce, domain)
		err := client.verifyVC20ForOIDC(t.Context(), session, envelope("eudi_pid", token))
		require.Error(t, err, "session.Nonce is not the challenge the wallet was asked for")
		require.Contains(t, err.Error(), "challenge")
	})

	t.Run("a session with no request-object nonce is refused", func(t *testing.T) {
		noNonce := w3cOIDCSession(nil)
		noNonce.RequestObjectNonce = ""
		token := present(t, "", domain)
		err := client.verifyVC20ForOIDC(t.Context(), noNonce, envelope("eudi_pid", token))
		require.Error(t, err, "binding to an empty challenge would accept anything")
		require.Contains(t, err.Error(), "request-object nonce")
	})
}

// TestVerifyVC20ForOIDCHonoursPerQueryHolderBinding: the UI path lets the
// DCQL query say binding is not required, and the same query is recoverable
// here. Requiring it unconditionally refused every response to a query that
// set require_cryptographic_holder_binding=false.
//
// The fail-closed half matters just as much: a document that cannot be
// attributed to a query carries no answer about binding, and "cannot tell"
// must mean required.
func TestVerifyVC20ForOIDCHonoursPerQueryHolderBinding(t *testing.T) {
	client, bareCredential, _ := w3cOIDCFixture(t)
	notRequired, required := false, true

	t.Run("a query that does not require binding accepts a bare credential", func(t *testing.T) {
		require.NoError(t, client.verifyVC20ForOIDC(t.Context(), w3cOIDCSession(&notRequired),
			envelope("eudi_pid", string(bareCredential))))
	})

	for name, binding := range map[string]*bool{
		"a query that requires binding": &required,
		"a query that says nothing":     nil,
	} {
		t.Run(name+" refuses a bare credential", func(t *testing.T) {
			err := client.verifyVC20ForOIDC(t.Context(), w3cOIDCSession(binding),
				envelope("eudi_pid", string(bareCredential)))
			require.Error(t, err, "an issuer-signed credential proves issuance, not that this holder is presenting it")
		})
	}

	t.Run("a scope whose query cannot be recovered fails closed", func(t *testing.T) {
		// The request object has aged out of the cache, so nothing says
		// what this scope asked for - including whether it asked for
		// binding. The OpenID4VP default is to require it, and "cannot
		// tell" must not become "not required".
		session := w3cOIDCSession(&notRequired)
		session.DCQLQuery = nil

		err := client.verifyVC20ForOIDC(t.Context(), session, string(bareCredential))
		require.Error(t, err, "an unrecoverable query must not relax binding")
		require.Contains(t, err.Error(), "W3C VC verification failed",
			"the refusal has to be the binding check itself, not a later one")
	})
}

// TestRefuseNonW3CAnswerToAW3CQuery: returning early when no W3C document is
// in the response let a wallet answer an ldp_vc query with an SD-JWT. Nothing
// else on this path compares the returned format against the requested one,
// so the W3C constraint was simply skipped.
func TestRefuseNonW3CAnswerToAW3CQuery(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	const sdJWT = "eyJhbGciOiJFUzI1NiJ9.x.y~"

	t.Run("an SD-JWT does not answer an ldp_vc query", func(t *testing.T) {
		err := client.verifyVC20ForOIDC(t.Context(), w3cOIDCSession(nil), envelope("eudi_pid", sdJWT))
		require.Error(t, err)
		require.Contains(t, err.Error(), "no W3C credential")
	})

	t.Run("a bare SD-JWT does not answer an ldp_vc query either", func(t *testing.T) {
		err := client.verifyVC20ForOIDC(t.Context(), w3cOIDCSession(nil), sdJWT)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no W3C credential")
	})

	t.Run("an SD-JWT answers an SD-JWT query", func(t *testing.T) {
		session := w3cOIDCSession(nil)
		session.DCQLQuery.Credentials[0].Format = openid4vp.FormatSDJWTVC
		session.DCQLQuery.Credentials[0].Meta = openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}
		require.NoError(t, client.verifyVC20ForOIDC(t.Context(), session, envelope("eudi_pid", sdJWT)))
	})
}

// TestVerifyVC20ForOIDCSeesThroughBase64: the VC20 decoder and
// detectCredentialFormat both accept a base64url- or standard-base64-wrapped
// JSON-LD document, so a guard that only looked for a leading '{' was
// side-stepped by encoding the same credential - and the claims extractor
// then read it unverified.
func TestVerifyVC20ForOIDCSeesThroughBase64(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	for name, wrapped := range map[string]string{
		"base64url": base64.RawURLEncoding.EncodeToString([]byte(unsignedW3CPresentation)),
		"base64":    base64.StdEncoding.EncodeToString([]byte(unsignedW3CPresentation)),
	} {
		t.Run(name, func(t *testing.T) {
			err := client.verifyVC20ForOIDC(t.Context(), w3cOIDCSession(nil), envelope("eudi_pid", wrapped))
			require.Error(t, err, "an encoded unsigned presentation must not walk past the guard")
			require.NotContains(t, err.Error(), "no W3C credential",
				"it has to be RECOGNISED as W3C, not merely refused for being absent")
		})
	}
}
