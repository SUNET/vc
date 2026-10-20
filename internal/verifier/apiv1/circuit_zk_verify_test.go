package apiv1

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/nymauth/circuits"
	"github.com/SUNET/vc/pkg/nymauth/verifier"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The offered circuit ids and proof systems come from THIS
// VERIFIER's configuration, never from the response.
//
// A request that offered neither list offered nothing, and the
// response validator then refuses every response - which is the
// intended reading rather than an oversight: a circuit this verifier
// never named is not one it can decide it trusts after seeing a proof
// from it.
func TestCircuitZkRequestTakesTheOfferFromConfiguration(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{
		PreferredVPFormats: &openid4vp.VPFormatsSupported{ZkpReq: &openid4vp.ZkpReqFormat{
			SystemIDValues:    []string{"urn:circuits:longfellow:nym_auth:v1"},
			ProofSystemValues: []string{"longfellow-libzk-v1"},
		}},
	}}}

	multiple := true
	query := openid4vp.CredentialQuery{
		ID:       "nym_attestation",
		Format:   openid4vp.FormatZkpReq,
		Multiple: &multiple,
		Req:      []openid4vp.ReqItem{{FnID: "age_check", Return: "age-1"}},
	}

	request := client.circuitZkRequestFor(query)
	assert.Equal(t, "nym_attestation", request.QueryID)
	assert.True(t, request.Multiple)
	assert.Equal(t, []string{"urn:circuits:longfellow:nym_auth:v1"}, request.OfferedSystemIDs)
	assert.Equal(t, query.Req, request.Items)
}

// A verifier that offered no circuit_zk formats offers nothing, and
// the empty lists are what makes the validator refuse.
func TestCircuitZkRequestWithNoOfferIsEmpty(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{}}}

	request := client.circuitZkRequestFor(openid4vp.CredentialQuery{ID: "q"})
	assert.Empty(t, request.OfferedSystemIDs)
	assert.Empty(t, request.OfferedSystemIDs)
	assert.False(t, request.Multiple, "DCQL multiple defaults to false")
}

// The channel decides the SessionTranscript, and a channel with no
// transcript builder is refused rather than given one of this
// verifier's invention.
//
// Both defined channels now have one; this is about the third that
// does not exist yet.
func TestCircuitZkSessionRefusesAnUnsupportedChannel(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{
		NymAuth: model.NymAuthVerifier{VerifierID: "x509_san_dns:verifier.example"},
	}}}

	_, err := client.circuitZkSessionFor(nil, circuitZkChannel("ble"), "https://verifier.example",
		"x509_san_dns:verifier.example", "pOA0oqEAhLnqug2r7Ve4tQ",
		"https://verifier.example/verification/direct_post", "eu.europa.ec.eudi.nym_auth.1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ble")
	assert.Contains(t, err.Error(), "pending shared vectors")
}

// The redirect channel builds the OpenID4VPHandover transcript, and
// it is NOT the DC API one. A wallet built one of the two; verifying
// against the other is an opaque proof failure, which is what the
// channel selection exists to prevent.
func TestCircuitZkSessionBuildsTheRedirectTranscript(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{
		NymAuth: model.NymAuthVerifier{VerifierID: "verifier.example"},
	}}}
	thumbprint := bytes.Repeat([]byte{0x11}, 32)

	session, err := client.circuitZkSessionFor(nil, channelOpenID4VP, "", "x509_san_dns:verifier.example",
		"pOA0oqEAhLnqug2r7Ve4tQ", "https://verifier.example/verification/direct_post",
		"eu.europa.ec.eudi.nym_auth.1", thumbprint)
	require.NoError(t, err)

	// The bytes the shared derive_redirect vectors fix, through the
	// package that is checked against them.
	want, err := verifier.MdocSessionTranscriptRedirect("x509_san_dns:verifier.example",
		"pOA0oqEAhLnqug2r7Ve4tQ", "https://verifier.example/verification/direct_post", thumbprint)
	require.NoError(t, err)
	assert.Equal(t, want, session.Transcript)

	dcAPI, err := client.circuitZkSessionFor(nil, channelDCAPI, "https://verifier.example", "",
		"pOA0oqEAhLnqug2r7Ve4tQ", "", "eu.europa.ec.eudi.nym_auth.1", thumbprint)
	require.NoError(t, err)
	assert.NotEqual(t, dcAPI.Transcript, session.Transcript, "two handovers, two transcripts")
}

// A redirect presentation whose response was not encrypted is refused
// here, where the message names the problem - not three calls later
// as a zero-length thumbprint.
func TestCircuitZkRedirectRequiresDirectPostJWT(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		refused bool
	}{
		{name: "encrypted", mode: openid4vp.ResponseModeDirectPostJWT},
		{name: "plain direct_post", mode: openid4vp.ResponseModeDirectPost, refused: true},
		{name: "form_post", mode: openid4vp.ResponseModeFormPost, refused: true},
		{name: "unset", mode: "", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkCircuitZkResponseMode(channelOpenID4VP, &cache.AuthorizationContext{ResponseMode: tc.mode})
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), openid4vp.ResponseModeDirectPostJWT)
			assert.Contains(t, err.Error(), "in the clear")
		})
	}

	// The DC API channel never crosses the network, and its handover
	// takes a null thumbprint for exactly that case.
	require.NoError(t, checkCircuitZkResponseMode(channelDCAPI,
		&cache.AuthorizationContext{ResponseMode: openid4vp.ResponseModeDirectPost}))

	// No session at all is a refusal, not a pass: "cannot establish
	// the response mode" must not read as "the response mode is fine".
	require.Error(t, checkCircuitZkResponseMode(channelOpenID4VP, nil))
}

// The DC API channel builds the transcript the circuits define, and
// verifier_input comes from the CONFIGURED bare verifier_id.
func TestCircuitZkSessionBuildsTheDCAPITranscript(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{
		NymAuth: model.NymAuthVerifier{VerifierID: "x509_san_dns:verifier.example"},
	}}}

	session, err := client.circuitZkSessionFor(nil, channelDCAPI, "https://verifier.example", "",
		"pOA0oqEAhLnqug2r7Ve4tQ", "", "eu.europa.ec.eudi.nym_auth.1", nil)
	require.NoError(t, err)

	assert.NotEmpty(t, session.Transcript)
	assert.Equal(t, "eu.europa.ec.eudi.nym_auth.1", session.DocType)
	assert.True(t, session.Now.IsZero(),
		"T is the prover's and belongs to the presentation, not the session")

	// The rulebook's MUST digest for the bare verifier_id.
	want, err := verifier.VerifierInput("x509_san_dns:verifier.example")
	require.NoError(t, err)
	assert.Equal(t, want, session.VerifierInput)
}

// A verifier_id that is a prefixed Client Identifier is refused here
// too, not only at startup: hashing it yields a pseudonym no other
// implementation reports, so a comparison never matches and the
// subject looks innocent.
func TestCircuitZkSessionUsesThePrefixedVerifierID(t *testing.T) {
	// v0.4 hashes the verifier_id exactly as published, prefix
	// included, and the archive's reference pseudonyms are computed
	// from that form. This test asserted the opposite until the rule
	// reversed on 2026-10-20.
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{
		NymAuth: model.NymAuthVerifier{VerifierID: "x509_san_dns:verifier.example"},
	}}}

	session, err := client.circuitZkSessionFor(nil, channelDCAPI, "https://verifier.example", "",
		"pOA0oqEAhLnqug2r7Ve4tQ", "", "eu.europa.ec.eudi.nym_auth.1", nil)
	require.NoError(t, err)

	want, err := verifier.VerifierInput("x509_san_dns:verifier.example")
	require.NoError(t, err)
	assert.Equal(t, want, session.VerifierInput)
	assert.Equal(t, "6eae85a0", hex.EncodeToString(session.VerifierInput[:])[:8],
		"the archive's own verifier_input for this client_id")

	// A marker with nothing after it still names no Verifier.
	client.cfg.Verifier.NymAuth.VerifierID = "x509_san_dns:"
	_, err = client.circuitZkSessionFor(nil, channelDCAPI, "https://verifier.example", "",
		"pOA0oqEAhLnqug2r7Ve4tQ", "", "eu.europa.ec.eudi.nym_auth.1", nil)
	assert.ErrorContains(t, err, "verifier_id")
}

// The age bounds come from the REQUEST's own parameters. Taking them
// from the response would be verifying a statement the holder chose.
func TestCircuitZkAgeBoundsComeFromTheRequest(t *testing.T) {
	bounds, err := circuitZkAgeBounds(openid4vp.ReqItem{
		FnID: "age_check", Return: "age-1",
		Params: map[string]any{"ge": "2008-10-10", "le": "2013-10-09"},
	})
	require.NoError(t, err)
	assert.Equal(t, "2008-10-10", bounds.Earliest)
	assert.Equal(t, "2013-10-09", bounds.Cutoff)

	_, err = circuitZkAgeBounds(openid4vp.ReqItem{
		FnID: "age_check", Return: "age-1", Params: map[string]any{"ge": 2008},
	})
	assert.ErrorContains(t, err, "is not a string")

	// A window narrower than the rulebook allows is refused by the
	// mapping, not passed to a circuit.
	_, err = circuitZkAgeBounds(openid4vp.ReqItem{
		FnID: "age_check", Return: "age-1",
		Params: map[string]any{"ge": "2008-01-01", "le": "2008-06-01"},
	})
	assert.ErrorContains(t, err, "at least 365")
}

// The published claims carry the pseudonyms the verifier RETURNED,
// never the ones the response claimed.
func TestCircuitZkCredentialPublishesTheVerifiedPseudonyms(t *testing.T) {
	claimed := make([]byte, 32)
	claimed[0] = 0xaa
	returned := make([]byte, 32)
	returned[0] = 0xbb

	presentation := openid4vp.ZkpPresentation{
		SystemID: "urn:c",

		Pseudonyms: map[string][]byte{"nym-1": claimed},
		Satisfied:  []string{"age-1"},
	}

	credential := circuitZkCredential("nym_auth", presentation, map[string][]byte{"nym-1": returned})

	encoded, err := json.Marshal(credential.Credential)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), base64.RawURLEncoding.EncodeToString(returned),
		"the published pseudonym is the one the verifier returned")
	assert.NotContains(t, string(encoded), base64.RawURLEncoding.EncodeToString(claimed),
		"and never the one the response claimed")
	assert.Equal(t, true, credential.Credential["age-1"])
	assert.Equal(t, "urn:c", credential.Credential["system_id"])
	assert.Equal(t, "nym_auth", credential.Scope)
}

// Without the native library there is no way to check a proof, and
// the stub must refuse rather than return a verified-looking nothing.
func TestCircuitZkNativeStubRefuses(t *testing.T) {
	if circuitZkNativeBuilt {
		t.Skip("this build has the zknative tag; the stub is not compiled in")
	}
	client := &Client{}
	_, err := client.verifyCircuitZkPresentation(t.Context(), openid4vp.ZkpPresentation{},
		circuitZkSession{}, nil, nil)
	assert.ErrorIs(t, err, ErrCircuitZkNotBuilt)
}

// The validator receives the whole vp_token ENVELOPE, which is what
// it expects - handing it one entry gave it an array where it wants a
// map, and the response then failed as unparseable.
//
// This runs the two halves together, through a circuit_zk-ONLY
// response, because that is the combination neither half's own tests
// exercised: the validator's vectors are whole envelopes, and the
// dispatch's tests never called the validator.
func TestCircuitZkRawTokenFeedsTheValidator(t *testing.T) {
	presentation := zkpPresentationB64(t, "urn:c",
		[][]byte{[]byte(strings.Repeat("c", 48))}, nowProofTime(),
		map[string]any{"age-1": true})
	body, err := json.Marshal(map[string]any{
		"state":    "s",
		"vp_token": map[string]any{"nym_attestation": []any{presentation}},
	})
	require.NoError(t, err)

	var response openid4vp.VPResponse
	require.NoError(t, json.Unmarshal(body, &response))

	raw, err := circuitZkRawToken(response, "nym_attestation")
	require.NoError(t, err)

	got, err := openid4vp.ValidateZkpReqResponse(raw, openid4vp.ZkpReqRequest{
		QueryID:          "nym_attestation",
		Items:            []openid4vp.ReqItem{{FnID: openid4vp.FunctionAgeCheck, Return: "age-1"}},
		OfferedSystemIDs: []string{"urn:c"},
		SourceFormat:     openid4vp.SourceFormatMsoMdoc,
	})
	require.NoError(t, err, "the dispatch must hand the validator what the validator expects")
	require.Len(t, got, 1)
	assert.Equal(t, []string{"age-1"}, got[0].Satisfied)
}

// A query the response does not answer is named as such, rather than
// reaching the validator as an envelope with a missing key.
func TestCircuitZkRawTokenRefusesAMissingQuery(t *testing.T) {
	var response openid4vp.VPResponse
	require.NoError(t, json.Unmarshal([]byte(`{"state":"s","vp_token":{"other":[{"a":1}]}}`), &response))

	_, err := circuitZkRawToken(response, "nym_attestation")
	assert.ErrorContains(t, err, "no presentation for credential query")
}

// The circuit_zk path is chosen by the scope's OWN credential query,
// never by requestedQuery's sole-query fallback.
//
// That fallback exists for a legacy session whose scope-to-query
// mapping was lost, and it is right where it is used: with exactly
// one query there is no ambiguity about which one a scope meant. As a
// ROUTING decision it is wrong. A scope that no query names would
// inherit the sole query's format, take the circuit_zk path, and have
// that query's presentation verified and cached under its own name -
// while the attribution check that refuses exactly this, in
// vpTokensForScope, sits on the branch that is no longer taken.
//
// Driven through the handler and not through requestedQueryExact,
// because the bug is WHICH lookup the routing line calls: a test on
// the helpers passes with either one wired up.
func TestCircuitZkRoutingIgnoresTheSingleQueryFallback(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	ctx := t.Context()

	openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{})
	require.NoError(t, err)
	client.openid4vp = openid4vpClient

	notifyService, err := notify.New(ctx, client.cfg, logger.NewSimple("test"))
	require.NoError(t, err)
	client.notify = notifyService

	const (
		kid   = "czk-routing-kid"
		state = "czk-routing-state"
	)
	_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(ctx, kid)
	require.NoError(t, err)
	// One circuit_zk query, and a scope that names none - the shape
	// "openid profile custom_claim" produces, where profile selects
	// the template and custom_claim is deliberately left unclaimed so
	// that it fails in the validation loop rather than vanishing.
	require.NoError(t, client.cacheService.AuthContext.Save(ctx, &cache.AuthorizationContext{
		SessionID:                "czk-routing-session",
		State:                    state,
		EphemeralEncryptionKeyID: kid,
		Nonce:                    "czk-routing-nonce",
		ClientID:                 "x509_san_dns:verifier.example.com",
		Scopes:                   []string{"custom_claim"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "nym_attestation",
			Format: openid4vp.FormatZkpReq,
			Meta:   openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
			Req: []openid4vp.ReqItem{{
				FnID:   openid4vp.FunctionAgeCheck,
				Return: "age-1",
				Params: map[string]any{"ge": "2008-10-10", "le": "2013-10-09"},
			}},
		}}},
	}))

	leaf := []byte(strings.Repeat("c", 48))
	plaintext, err := json.Marshal(map[string]any{
		"state": state,
		"vp_token": map[string]any{
			"nym_attestation": []any{zkpPresentationB64(t,
				"urn:circuits:longfellow:nym_auth:v1",
				[][]byte{leaf}, nowProofTime(),
				map[string]any{"age-1": true},
			)},
		},
	})
	require.NoError(t, err)
	body, err := jwe.Encrypt(plaintext,
		jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	require.NoError(t, err)

	_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(body)})
	require.Error(t, err, "an unclaimed scope cannot be satisfied by another query's presentation")
	assert.Contains(t, err.Error(), "names no credential query in this request",
		"the unclaimed scope must be refused by the attribution check")
	assert.NotContains(t, err.Error(), "circuit_zk",
		"it must never have reached the circuit_zk path: that path has no attribution check")
}

// The response-mode rule has to be ENFORCED, not merely implemented.
//
// Driven through VerificationDirectPost, because a test on
// checkCircuitZkResponseMode alone passes whether or not
// verifyCircuitZkScope calls it - which is the mistake that would
// actually ship: the function exists, reads correctly, and nothing
// invokes it.
func TestCircuitZkRedirectResponseModeIsEnforcedByTheHandler(t *testing.T) {
	ctx := t.Context()

	post := func(t *testing.T, responseMode string) error {
		t.Helper()
		client, _ := CreateTestClientWithMock(t, nil)

		openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{})
		require.NoError(t, err)
		client.openid4vp = openid4vpClient

		notifyService, err := notify.New(ctx, client.cfg, logger.NewSimple("test"))
		require.NoError(t, err)
		client.notify = notifyService

		// An empty allowlist is enough: the response-mode check runs
		// before any circuit is loaded, and this is about reaching it.
		client.nymAuthCircuits, err = circuits.NewAllowlist(model.NymAuthCircuits{})
		require.NoError(t, err)
		client.cfg.Verifier.NymAuth.VerifierID = "verifier.example"
		client.cfg.Verifier.PreferredVPFormats = &openid4vp.VPFormatsSupported{
			ZkpReq: &openid4vp.ZkpReqFormat{
				SystemIDValues:    []string{"urn:circuits:longfellow:nym_auth:v1"},
				ProofSystemValues: []string{"longfellow-libzk-v1"},
			},
		}

		const kid = "czk-mode-kid"
		state := "czk-mode-state-" + responseMode
		_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(ctx, kid)
		require.NoError(t, err)

		require.NoError(t, client.cacheService.AuthContext.Save(ctx, &cache.AuthorizationContext{
			SessionID:                "czk-mode-session",
			State:                    state,
			Nonce:                    "pOA0oqEAhLnqug2r7Ve4tQ",
			ClientID:                 "x509_san_dns:verifier.example",
			ResponseMode:             responseMode,
			EphemeralEncryptionKeyID: kid,
			Scopes:                   []string{"nym_attestation"},
			DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
				ID:     "nym_attestation",
				Format: openid4vp.FormatZkpReq,
				Meta:   openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
				Req: []openid4vp.ReqItem{{
					FnID:   openid4vp.FunctionAgeCheck,
					Return: "age-1",
					Params: map[string]any{"ge": "2008-10-10", "le": "2013-10-09"},
				}},
			}}},
		}))

		presentation := zkpPresentationB64(t, "urn:circuits:longfellow:nym_auth:v1",
			[][]byte{[]byte(strings.Repeat("c", 48))}, nowProofTime(),
			map[string]any{"age-1": true})
		plaintext, err := json.Marshal(map[string]any{
			"state":    state,
			"vp_token": map[string]any{"nym_attestation": []any{presentation}},
		})
		require.NoError(t, err)
		body, err := jwe.Encrypt(plaintext,
			jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)

		// DCAPI false: this is the redirect channel.
		_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(body)})
		return err
	}

	err := post(t, openid4vp.ResponseModeDirectPost)
	require.Error(t, err, "an unencrypted redirect response must be refused")
	assert.Contains(t, err.Error(), openid4vp.ResponseModeDirectPostJWT)
	assert.Contains(t, err.Error(), "in the clear")

	// With direct_post.jwt the response mode is accepted, and the
	// request fails LATER - on the circuit, which this build cannot
	// load. That is the point: a different failure means the mode
	// check passed rather than that everything works.
	err = post(t, openid4vp.ResponseModeDirectPostJWT)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "in the clear",
		"direct_post.jwt must get past the response-mode check")
}

// The session a real UI interaction creates must carry the response
// mode the wallet was actually told to use.
//
// Without this, every QR or link circuit_zk presentation from an
// ordinary session is refused with response_mode "" before the proof
// is ever checked - and the handler test above does not catch it,
// because it builds its own session and sets the field by hand.
// Which is the point: a test that constructs the state it is
// verifying cannot discover that nothing else constructs it.
func TestUIInteractionSessionRecordsTheResponseMode(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)

	reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
	require.NoError(t, err)
	require.NotEmpty(t, reply.SessionID)

	session, err := client.cacheService.AuthContext.GetByID(ctx, reply.SessionID)
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.Equal(t, openid4vp.ResponseModeDirectPostJWT, session.ResponseMode,
		"the link and QR request object carries direct_post.jwt, so the session must say so")

	// And it is the mode a redirect circuit_zk presentation is
	// checked against, so a real session passes that check.
	require.NoError(t, checkCircuitZkResponseMode(channelOpenID4VP, session),
		"a session minted by UIInteraction must satisfy the redirect response-mode rule")
}

// T is the PROVER'S proof_time, checked against this verifier's
// clock rather than replaced by it.
//
// The circuit binds all 20 bytes of T into its public inputs, so only
// the prover knows which second it proved at. The window is what
// makes accepting that value safe.
func TestCircuitZkProofTimeAcceptsAValueInsideTheWindow(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{}}}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

	proved := now.Add(-30 * time.Second)
	got, err := client.circuitZkProofTime(openid4vp.ZkpPresentation{
		HasProofTime: true, ProofTime: proved,
	}, now)
	require.NoError(t, err)
	assert.True(t, got.Equal(proved), "T is the prover's value, unchanged")
}

// Outside the window is REFUSED, not clamped, and the message names
// the deviation and the limit - the operator's next question is
// always "by how much".
func TestCircuitZkProofTimeRefusesOutsideTheWindow(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{}}}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		at    time.Time
		names string
	}{
		{name: "too far ahead", at: now.Add(2 * time.Minute), names: "in the future"},
		{name: "too old", at: now.Add(-20 * time.Minute), names: "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.circuitZkProofTime(openid4vp.ZkpPresentation{
				HasProofTime: true, ProofTime: tc.at,
			}, now)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.names)
		})
	}

	// And no proof_time at all is a refusal: a proof checked against a
	// guessed T is not checked.
	_, err := client.circuitZkProofTime(openid4vp.ZkpPresentation{}, now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no proof_time")
}

// The window is configurable, and defaults to the shared
// recommendation when a deployment has not chosen.
func TestCircuitZkToleranceDefaultsToTheRecommendation(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{}}}
	skew, maxAge := client.circuitZkTolerance()
	assert.Equal(t, openid4vp.RecommendedSkew, skew)
	assert.Equal(t, openid4vp.RecommendedMaxAge, maxAge)

	client.cfg.Verifier.NymAuth.ProofTimeSkewSeconds = 5
	client.cfg.Verifier.NymAuth.ProofTimeMaxAgeSeconds = 7
	skew, maxAge = client.circuitZkTolerance()
	assert.Equal(t, 5*time.Second, skew)
	assert.Equal(t, 7*time.Second, maxAge)
}

// zkpPresentationB64 builds one presentation the way a prover does:
// CBOR, then unpadded base64url.
//
// Written out here rather than hand-coded as a constant so a test
// reads as the shape it means. The validator's own conformance is
// pinned by the vendored vectors in pkg/openid4vp; what these tests
// need is a presentation that gets PAST it, so the dispatch and the
// trust path can be exercised.
func zkpPresentationB64(t *testing.T, systemID string, keySet [][]byte, proofTime string, results map[string]any) string {
	t.Helper()

	presentation := map[string]any{
		"system_id":      systemID,
		"proof":          []byte(strings.Repeat("p", 48)),
		"issuer_key_set": keySet,
		"results":        results,
	}
	if proofTime != "" {
		parsed, err := openid4vp.ParseProofTime(proofTime)
		require.NoError(t, err)
		presentation["proof_time"] = cbor.Tag{Number: 0, Content: parsed.UTC().Format(openid4vp.ProofTimeLayout)}
	}
	encoder, err := cbor.EncOptions{Sort: cbor.SortCanonical}.EncMode()
	require.NoError(t, err)
	encoded, err := encoder.Marshal(presentation)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// nowProofTime is a proof_time inside any sane tolerance window.
func nowProofTime() string { return openid4vp.RenderProofTimeOrPanic(time.Now()) }
