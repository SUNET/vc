package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
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
		PreferredVPFormats: &openid4vp.VPFormatsSupported{CircuitZk: &openid4vp.CircuitZkFormat{
			CircuitIDValues:          []string{"urn:circuits:longfellow:nym_auth:v1"},
			CircuitProofSystemValues: []string{"longfellow-libzk-v1"},
		}},
	}}}

	multiple := true
	query := openid4vp.CredentialQuery{
		ID:       "nym_attestation",
		Format:   openid4vp.FormatCircuitZk,
		Multiple: &multiple,
		Req:      []openid4vp.ReqItem{{ID: "age_check", Return: "age-1"}},
	}

	request := client.circuitZkRequestFor(query)
	assert.Equal(t, "nym_attestation", request.QueryID)
	assert.True(t, request.Multiple)
	assert.Equal(t, []string{"urn:circuits:longfellow:nym_auth:v1"}, request.OfferedCircuitIDs)
	assert.Equal(t, []string{"longfellow-libzk-v1"}, request.OfferedProofSystems)
	assert.Equal(t, query.Req, request.Items)
}

// A verifier that offered no circuit_zk formats offers nothing, and
// the empty lists are what makes the validator refuse.
func TestCircuitZkRequestWithNoOfferIsEmpty(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{}}}

	request := client.circuitZkRequestFor(openid4vp.CredentialQuery{ID: "q"})
	assert.Empty(t, request.OfferedCircuitIDs)
	assert.Empty(t, request.OfferedProofSystems)
	assert.False(t, request.Multiple, "DCQL multiple defaults to false")
}

// The channel decides the SessionTranscript, and a channel with no
// transcript builder is refused rather than given one of this
// verifier's invention.
func TestCircuitZkSessionRefusesAnUnsupportedChannel(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{
		NymAuth: model.NymAuthVerifier{VerifierID: "verifier.example"},
	}}}

	_, err := client.circuitZkSessionFor(nil, channelOpenID4VP, "https://verifier.example",
		"x509_san_dns:verifier.example", "pOA0oqEAhLnqug2r7Ve4tQ",
		"https://verifier.example/verification/direct_post", "eu.europa.ec.eudi.nym_auth.1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), string(channelOpenID4VP))
	assert.Contains(t, err.Error(), "pending shared vectors")
}

// The DC API channel builds the transcript the circuits define, and
// verifier_input comes from the CONFIGURED bare verifier_id.
func TestCircuitZkSessionBuildsTheDCAPITranscript(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{
		NymAuth: model.NymAuthVerifier{VerifierID: "verifier.example"},
	}}}

	session, err := client.circuitZkSessionFor(nil, channelDCAPI, "https://verifier.example", "",
		"pOA0oqEAhLnqug2r7Ve4tQ", "", "eu.europa.ec.eudi.nym_auth.1", nil)
	require.NoError(t, err)

	assert.NotEmpty(t, session.Transcript)
	assert.Equal(t, "eu.europa.ec.eudi.nym_auth.1", session.DocType)
	assert.False(t, session.Now.IsZero())

	// The rulebook's MUST digest for the bare verifier_id.
	want, err := verifier.VerifierInput("verifier.example")
	require.NoError(t, err)
	assert.Equal(t, want, session.VerifierInput)
}

// A verifier_id that is a prefixed Client Identifier is refused here
// too, not only at startup: hashing it yields a pseudonym no other
// implementation reports, so a comparison never matches and the
// subject looks innocent.
func TestCircuitZkSessionRefusesAPrefixedVerifierID(t *testing.T) {
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{
		NymAuth: model.NymAuthVerifier{VerifierID: "x509_san_dns:verifier.example"},
	}}}

	_, err := client.circuitZkSessionFor(nil, channelDCAPI, "https://verifier.example", "",
		"pOA0oqEAhLnqug2r7Ve4tQ", "", "eu.europa.ec.eudi.nym_auth.1", nil)
	assert.ErrorContains(t, err, "verifier_id")
}

// The age bounds come from the REQUEST's own parameters. Taking them
// from the response would be verifying a statement the holder chose.
func TestCircuitZkAgeBoundsComeFromTheRequest(t *testing.T) {
	bounds, err := circuitZkAgeBounds(openid4vp.ReqItem{
		ID: "age_check", Return: "age-1",
		Params: map[string]any{"ge": "2008-10-10", "le": "2013-10-09"},
	})
	require.NoError(t, err)
	assert.Equal(t, "2008-10-10", bounds.Earliest)
	assert.Equal(t, "2013-10-09", bounds.Cutoff)

	_, err = circuitZkAgeBounds(openid4vp.ReqItem{
		ID: "age_check", Return: "age-1", Params: map[string]any{"ge": 2008},
	})
	assert.ErrorContains(t, err, "is not a string")

	// A window narrower than the rulebook allows is refused by the
	// mapping, not passed to a circuit.
	_, err = circuitZkAgeBounds(openid4vp.ReqItem{
		ID: "age_check", Return: "age-1",
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

	presentation := openid4vp.CircuitZkPresentation{
		CircuitID:   "urn:c",
		ProofSystem: "longfellow-libzk-v1",
		Pseudonyms:  map[string][]byte{"nym-1": claimed},
		Satisfied:   []string{"age-1"},
	}

	credential := circuitZkCredential("nym_auth", presentation, map[string][]byte{"nym-1": returned})

	encoded, err := json.Marshal(credential.Credential)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), base64.RawURLEncoding.EncodeToString(returned),
		"the published pseudonym is the one the verifier returned")
	assert.NotContains(t, string(encoded), base64.RawURLEncoding.EncodeToString(claimed),
		"and never the one the response claimed")
	assert.Equal(t, true, credential.Credential["age-1"])
	assert.Equal(t, "urn:c", credential.Credential["circuit_id"])
	assert.Equal(t, "nym_auth", credential.Scope)
}

// Without the native library there is no way to check a proof, and
// the stub must refuse rather than return a verified-looking nothing.
func TestCircuitZkNativeStubRefuses(t *testing.T) {
	if circuitZkNativeBuilt {
		t.Skip("this build has the zknative tag; the stub is not compiled in")
	}
	client := &Client{}
	_, err := client.verifyCircuitZkPresentation(t.Context(), openid4vp.CircuitZkPresentation{},
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
	const body = `{
	  "state": "s",
	  "vp_token": {
	    "nym_attestation": [{
	      "circuit_id": "urn:c",
	      "proof_system": "longfellow-libzk-v1",
	      "proof": "AQID",
	      "x5chain": ["Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2Nj"],
	      "results": {"age-1": {"satisfied": true}}
	    }]
	  }
	}`

	var response openid4vp.VPResponse
	require.NoError(t, json.Unmarshal([]byte(body), &response))

	raw, err := circuitZkRawToken(response, "nym_attestation")
	require.NoError(t, err)

	got, err := openid4vp.ValidateCircuitZkResponse(raw, openid4vp.CircuitZkRequest{
		QueryID:             "nym_attestation",
		Items:               []openid4vp.ReqItem{{ID: openid4vp.CircuitZkFunctionAgeCheck, Return: "age-1"}},
		OfferedCircuitIDs:   []string{"urn:c"},
		OfferedProofSystems: []string{"longfellow-libzk-v1"},
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
			Format: openid4vp.FormatCircuitZk,
			Meta:   openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
			Req: []openid4vp.ReqItem{{
				ID:     openid4vp.CircuitZkFunctionAgeCheck,
				Return: "age-1",
				Params: map[string]any{"ge": "2008-10-10", "le": "2013-10-09"},
			}},
		}}},
	}))

	leaf := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 48)))
	plaintext, err := json.Marshal(map[string]any{
		"state": state,
		"vp_token": map[string]any{
			"nym_attestation": []any{map[string]any{
				"circuit_id":   "urn:circuits:longfellow:nym_auth:v1",
				"proof_system": "longfellow-libzk-v1",
				"proof":        base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 48))),
				"x5chain":      []string{leaf},
				"results":      map[string]any{"age-1": map[string]any{"satisfied": true}},
			}},
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

// T is decided in ONE place, and that place says where the value
// came from.
//
// It is the receipt time today, which is known to be wrong: the
// circuit binds all 20 bytes of T into its public inputs, so a prover
// that used any other second produces a proof that cannot verify. The
// fix needs a cross-implementation decision and is tracked on #830.
// What is asserted here is the structure that makes the fix small -
// one function, and a recorded source - and the diagnostics that stop
// the failure reading as a bad proof.
func TestCircuitZkProofTimeNamesItsSource(t *testing.T) {
	now, source := circuitZkProofTime(nil)

	assert.False(t, now.IsZero(), "T must be a real timestamp")
	assert.Equal(t, proofTimeReceipt, source)
	assert.Contains(t, source, "PROVISIONAL",
		"the source string is what an operator sees in the log; it has to say this one cannot match")
}

// A verification failure under the provisional T names the likeliest
// cause, instead of leaving an operator to suspect the circuit, the
// artifact or the issuer key.
func TestCircuitZkTimeBindingHintExplainsTheProvisionalT(t *testing.T) {
	provisional := circuitZkSession{
		Now:       time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC),
		NowSource: proofTimeReceipt,
	}
	hint := circuitZkTimeBindingHint(provisional)

	assert.Contains(t, hint, "2026-10-20T09:30:00Z", "the T actually used")
	assert.Contains(t, hint, proofTimeReceipt, "and where it came from")
	assert.Contains(t, hint, "830", "and where the explanation lives")

	// And it EXPIRES. Once T comes from the session the hint is empty,
	// so a genuine bad proof is not annotated with a cause that no
	// longer applies - which would be its own wild goose chase.
	settled := provisional
	settled.NowSource = proofTimeSession
	assert.Empty(t, circuitZkTimeBindingHint(settled),
		"the hint must disappear with the gap it describes")
}
