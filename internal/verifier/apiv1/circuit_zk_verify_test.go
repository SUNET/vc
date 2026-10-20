package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/nymauth/verifier"
	"github.com/SUNET/vc/pkg/openid4vp"

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

	_, err := client.circuitZkSessionFor(channelOpenID4VP, "https://verifier.example",
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

	session, err := client.circuitZkSessionFor(channelDCAPI, "https://verifier.example", "",
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

	_, err := client.circuitZkSessionFor(channelDCAPI, "https://verifier.example", "",
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
