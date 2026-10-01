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

	err := client.verifyVC20ForOIDC(t.Context(), w3cOIDCSession(nil), unsignedW3CPresentation)
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

	session := sdJWTSession()

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
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "pid",
			Format: openid4vp.FormatLdpVCDCQL,
			Meta: openid4vp.MetaQuery{TypeValues: [][]string{
				{openid4vp.BaseVCTypeIRI},
			}},
		}}},
		ScopeQueryIDs:      map[string]string{"pid": "pid"},
		RequestObjectNonce: "the-request-objects-nonce",
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

	err := client.verifyVC20ForOIDC(t.Context(), w3cOIDCSession(nil), twoCredentials)
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
			query := openid4vp.CredentialQuery{
				ID: "eudi_pid", Format: format,
				Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}, DoctypeValue: "eu.europa.ec.eudi.pid.1"},
			}
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

// sdJWTSession is a request for one SD-JWT under scope "pid". The gate needs
// a recoverable query on every response, so even a case about non-W3C
// responses has to carry the request that was actually made.
func sdJWTSession() *cache.AuthorizationContext {
	return &cache.AuthorizationContext{
		Nonce:              "the-clients-oidc-nonce",
		RequestObjectNonce: "the-request-objects-nonce",
		ClientID:           "relying-party-oauth-client-id",
		Scopes:             []string{"openid", "pid"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "pid",
			Format: openid4vp.FormatSDJWTVC,
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}},
		}}},
		ScopeQueryIDs: map[string]string{"pid": "pid"},
	}
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
		// The scope-to-query mapping is gone - a session cached before
		// #683, or one a rebuild could not reconstruct - and the request
		// carries two queries, so nothing says which one this scope was
		// asked under. requestedQuery guesses only when there is exactly
		// one and no ambiguity; here there is, so nothing says whether
		// binding was required either. The OpenID4VP default is to
		// require it, and "cannot tell" must not become "not required".
		session := w3cOIDCSession(&notRequired)
		session.Scopes = append(session.Scopes, "ehic")
		second := session.DCQLQuery.Credentials[0]
		second.ID = "eudi_ehic"
		session.DCQLQuery.Credentials = append(session.DCQLQuery.Credentials, second)
		session.ScopeQueryIDs = nil

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

// TestVerifyVC20ForOIDCFailsClosedWhenTheRequestIsGone: createDCQLQuery
// builds a query for every session this flow creates, so a session with none
// means the persisted request is gone - a replica that cannot read it is the
// plain case. Returning success there bypassed the gate in exactly the
// failure mode it exists for: no scope can be found, so no format is
// compared, and an SD-JWT answers a W3C request unverified.
func TestVerifyVC20ForOIDCFailsClosedWhenTheRequestIsGone(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	session := w3cOIDCSession(nil)
	session.DCQLQuery = nil

	for name, token := range map[string]string{
		"an SD-JWT":          "eyJhbGciOiJFUzI1NiJ9.x.y~",
		"a DCQL envelope":    `{"eudi_pid": ["eyJhbGciOiJFUzI1NiJ9.x.y~"]}`,
		"a W3C presentation": unsignedW3CPresentation,
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			err := client.verifyVC20ForOIDC(t.Context(), session, token)
			require.Error(t, err, "a response that cannot be checked against a request must not be accepted")
			require.Contains(t, err.Error(), "no longer available")
		})
	}
}

// TestVerifyVC20ForOIDCRefusesAMixedResponse: this gate verifies W3C
// documents and nothing else, while extractAndMapClaims merges EVERY token
// in the response. An SD-JWT or mdoc riding alongside a verified credential
// therefore has its claims injected unverified - and the presence of the
// verified one is what makes the response look checked.
func TestVerifyVC20ForOIDCRefusesAMixedResponse(t *testing.T) {
	client, _, present := w3cOIDCFixture(t)
	domain, err := client.cfg.Verifier.VerifierClientID(client.pkiSigningCert)
	require.NoError(t, err)

	session := w3cOIDCSession(nil)
	session.Scopes = append(session.Scopes, "ehic")
	session.DCQLQuery.Credentials = append(session.DCQLQuery.Credentials, openid4vp.CredentialQuery{
		ID:     "eudi_ehic",
		Format: openid4vp.FormatSDJWTVC,
		Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:ehic:1"}},
	})
	session.ScopeQueryIDs["ehic"] = "eudi_ehic"

	mixed, err := json.Marshal(map[string][]string{
		"eudi_pid":  {present(t, session.RequestObjectNonce, domain)},
		"eudi_ehic": {"eyJhbGciOiJFUzI1NiJ9.x.y~"},
	})
	require.NoError(t, err)

	verifyErr := client.verifyVC20ForOIDC(t.Context(), session, string(mixed))
	require.Error(t, verifyErr, "the unverified half must not ride in on the verified one")
	require.Contains(t, verifyErr.Error(), "does not verify")
}

// TestHandleDirectPostRefusesAnUnverifiedW3CToken: HandleDirectPost stores
// the extracted claims and issues an authorization code without checking a
// signature anywhere, for any format. Making W3C documents readable by
// extractAndMapClaims added a new way through that: an unsigned
// credential's credentialSubject would be mapped straight into the session.
//
// The refusal is W3C-only on purpose. This handler is registered on no
// route - the two endpoints that verify are VerificationDirectPost and
// ProcessDirectPost - and its non-W3C behaviour is the pre-existing, wider
// gap, which this branch neither widens nor is the place to close.
func TestHandleDirectPostRefusesAnUnverifiedW3CToken(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	const sessionID = "session-handle-direct-post-w3c"
	session := w3cOIDCSession(nil)
	session.SessionID = sessionID
	session.Status = cache.SessionStatusPending
	session.CreatedAt = time.Now()
	session.ExpiresAt = time.Now().Add(10 * time.Minute).Unix()
	session.RedirectURI = "https://client.example.com/callback"
	session.State = sessionID
	require.NoError(t, client.cacheService.AuthContext.Create(ctx, session))

	err := client.HandleDirectPost(ctx, sessionID, unsignedW3CPresentation, nil)
	require.Error(t, err, "an unsigned W3C presentation must not be accepted here either")
	require.ErrorIs(t, err, ErrInvalidVP)

	stored, err := client.cacheService.AuthContext.GetByID(ctx, sessionID)
	require.NoError(t, err)
	require.Empty(t, stored.VerifiedClaims, "nothing from an unverified document may reach the session")
	require.Empty(t, stored.Code, "and no authorization code may be issued for it")

	// Base64 does not get round it: the same detection the verified paths
	// use is what decides here.
	require.ErrorIs(t,
		client.HandleDirectPost(ctx, sessionID, base64.RawURLEncoding.EncodeToString([]byte(unsignedW3CPresentation)), nil),
		ErrInvalidVP)

	// And a non-W3C response is untouched by this refusal, or the handler
	// would be broken rather than guarded.
	const otherSession = "session-handle-direct-post-sdjwt"
	sdjwt := sdJWTSession()
	sdjwt.SessionID = otherSession
	sdjwt.Status = cache.SessionStatusPending
	sdjwt.CreatedAt = time.Now()
	sdjwt.ExpiresAt = time.Now().Add(10 * time.Minute).Unix()
	sdjwt.RedirectURI = "https://client.example.com/callback"
	sdjwt.State = otherSession
	require.NoError(t, client.cacheService.AuthContext.Create(ctx, sdjwt))
	require.NoError(t, client.HandleDirectPost(ctx, otherSession, "eyJhbGciOiJFUzI1NiJ9.x.y~", nil))
}

// TestVerifyVC20ForOIDCRefusesExtraCredentialsForOneQuery:
// CredentialQuery.Multiple defaults to false, and the claim extraction that
// follows MERGES every token returned under a query - so a wallet appending
// a second credential could overwrite the first one's claims in the session
// even though the request never permitted more than one. Both verify; that
// is not the question.
func TestVerifyVC20ForOIDCRefusesExtraCredentialsForOneQuery(t *testing.T) {
	client, _, present := w3cOIDCFixture(t)
	domain, err := client.cfg.Verifier.VerifierClientID(client.pkiSigningCert)
	require.NoError(t, err)

	session := w3cOIDCSession(nil)
	token := present(t, session.RequestObjectNonce, domain)

	two, err := json.Marshal(map[string][]string{"eudi_pid": {token, token}})
	require.NoError(t, err)

	err = client.verifyVC20ForOIDC(t.Context(), session, string(two))
	require.Error(t, err, "a query that did not ask for multiple credentials must not be answered with two")
	require.Contains(t, err.Error(), "did not permit")

	// multiple: true is the wallet's licence to return more than one, and
	// then it must be accepted.
	permitted := w3cOIDCSession(nil)
	permitted.DCQLQuery.Credentials[0].Multiple = true
	require.NoError(t, client.verifyVC20ForOIDC(t.Context(), permitted, string(two)))
}

// TestVerifyVC20ForOIDCRefusesAnUnansweredScope: a request for a W3C
// credential AND an SD-JWT, answered with the W3C half alone, carries no
// unverified token to refuse - and the session then completes with nothing
// for the scope that asked for the other one. Nothing downstream compares
// the response against the request, so this is the only place it can be
// seen.
func TestVerifyVC20ForOIDCRefusesAnUnansweredScope(t *testing.T) {
	client, _, present := w3cOIDCFixture(t)
	domain, err := client.cfg.Verifier.VerifierClientID(client.pkiSigningCert)
	require.NoError(t, err)

	session := w3cOIDCSession(nil)
	session.Scopes = append(session.Scopes, "ehic")
	session.DCQLQuery.Credentials = append(session.DCQLQuery.Credentials, openid4vp.CredentialQuery{
		ID:     "eudi_ehic",
		Format: openid4vp.FormatSDJWTVC,
		Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:ehic:1"}},
	})
	session.ScopeQueryIDs["ehic"] = "eudi_ehic"

	onlyW3C, err := json.Marshal(map[string][]string{
		"eudi_pid": {present(t, session.RequestObjectNonce, domain)},
	})
	require.NoError(t, err)

	err = client.verifyVC20ForOIDC(t.Context(), session, string(onlyW3C))
	require.Error(t, err, "the SD-JWT scope was requested and nothing answered it")
	require.Contains(t, err.Error(), "ehic")
}

// TestVerifyVC20ForOIDCDoesNotRelaxOnTheSingleQueryFallback: requestedQuery
// returns the only credential query when a scope maps to none, which is
// right for applying a CONSTRAINT and wrong for reading a RELAXATION. "The
// mapping is gone, so take the only query's settings" turned
// require_cryptographic_holder_binding=false and multiple=true into the
// answer for a scope nobody established that query belongs to - so a guard
// meant to fail closed failed open whenever a request carried exactly one
// query.
func TestVerifyVC20ForOIDCDoesNotRelaxOnTheSingleQueryFallback(t *testing.T) {
	client, bareCredential, present := w3cOIDCFixture(t)
	domain, err := client.cfg.Verifier.VerifierClientID(client.pkiSigningCert)
	require.NoError(t, err)
	notRequired := false

	// One credential query, and a scope that names no query: the mapping is
	// empty and the query's id is not the scope.
	unmapped := func() *cache.AuthorizationContext {
		session := w3cOIDCSession(&notRequired)
		session.DCQLQuery.Credentials[0].ID = "a_query_id_no_scope_names"
		session.ScopeQueryIDs = nil
		return session
	}

	t.Run("holder binding stays required", func(t *testing.T) {
		err := client.verifyVC20ForOIDC(t.Context(), unmapped(), string(bareCredential))
		require.Error(t, err, "binding must not be switched off by a query the fallback guessed")
		require.Contains(t, err.Error(), "W3C VC verification failed")
	})

	t.Run("multiple credentials stay refused", func(t *testing.T) {
		session := unmapped()
		session.DCQLQuery.Credentials[0].Multiple = true

		// Keyed by "" so the response still COVERS the one credential
		// scope - otherwise the coverage check refuses it first and this
		// subtest proves nothing about the fallback.
		token := present(t, session.RequestObjectNonce, domain)
		two, err := json.Marshal(map[string][]string{"": {token, token}})
		require.NoError(t, err)

		err = client.verifyVC20ForOIDC(t.Context(), session, string(two))
		require.Error(t, err, "permission for several credentials must not come from a guessed query")
		require.Contains(t, err.Error(), "did not permit")
	})

	// The constraint half still uses the fallback, and must: with one query
	// there is no ambiguity about which credential was asked for, and
	// applying its type_values narrows rather than widens. A credential of
	// the wrong type is still refused for an unmapped scope.
	t.Run("the type constraint still applies", func(t *testing.T) {
		session := unmapped()
		session.DCQLQuery.Credentials[0].Meta.TypeValues = [][]string{
			{openid4vp.BaseVCTypeIRI, "https://example.org/degree#DoctoralDegreeCredential"},
		}

		err := client.verifyVC20ForOIDC(t.Context(), session, present(t, session.RequestObjectNonce, domain))
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not have a type the request asked for")
	})
}
