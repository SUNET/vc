package apiv1

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPSC() (hexValue, claimValue string) {
	sum := sha256.Sum256([]byte("a-private-seed"))
	return hex.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(sum[:])
}

// The commitment is read from the proof JWT as unpadded base64url of
// exactly 32 bytes, and anything else is refused rather than coerced.
//
// Unpadded per RFC 7515 section 2, like every other binary value in a
// JWT. Accepting padded as well would let two wallets disagree about
// the encoding of a value that has to match byte for byte across
// issuances - and the second one would look like a different subject.
func TestPSCFromProofClaims(t *testing.T) {
	want, claim := testPSC()

	t.Run("the advertised claim", func(t *testing.T) {
		got, err := pscFromProofClaims(map[string]any{model.PSCProofClaim: claim})
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("absent is not an error here", func(t *testing.T) {
		// So a caller can tell "not sent" from "sent wrong": one is a
		// wallet that did not see the advertisement, the other is a
		// wallet that got the encoding wrong.
		got, err := pscFromProofClaims(map[string]any{"nonce": "n"})
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("padded base64url is refused", func(t *testing.T) {
		raw, err := hex.DecodeString(want)
		require.NoError(t, err)
		_, err = pscFromProofClaims(map[string]any{model.PSCProofClaim: base64.URLEncoding.EncodeToString(raw)})
		assert.ErrorContains(t, err, "unpadded base64url")
	})

	t.Run("standard base64 is refused", func(t *testing.T) {
		// "+" and "/" are not in the base64url alphabet, so a wallet
		// using the wrong one is caught rather than silently decoding
		// to different bytes.
		_, err := pscFromProofClaims(map[string]any{model.PSCProofClaim: "a+b/c"})
		assert.Error(t, err)
	})

	t.Run("the wrong length is refused", func(t *testing.T) {
		_, err := pscFromProofClaims(map[string]any{model.PSCProofClaim: base64.RawURLEncoding.EncodeToString([]byte("short"))})
		assert.ErrorContains(t, err, "a commitment is 32")
	})

	t.Run("a non-string claim is refused", func(t *testing.T) {
		_, err := pscFromProofClaims(map[string]any{model.PSCProofClaim: 42})
		assert.ErrorContains(t, err, "not a string")
	})
}

// The conflict is HTTP 400, a marked prefix the SDK matches on, and
// then the sentence a person reads.
func TestPSCConflictError(t *testing.T) {
	err := pscConflictError()
	assert.Equal(t, openid4vci.ErrInvalidCredentialRequest, err.Err)
	assert.Equal(t, 400, openid4vci.StatusCode(err))

	description, ok := err.ErrorDescription.(string)
	require.True(t, ok, "the SDK reads it as a string")
	assert.True(t, strings.HasPrefix(description, model.PSCConflictPrefix),
		"the SDK matches on the prefix to surface this distinguishably")
	assert.Contains(t, description, "operator-approved reset")

	hexValue, claim := testPSC()
	assert.NotContains(t, description, hexValue, "the refusal must not echo a commitment")
	assert.NotContains(t, description, claim)
}

// The advertisement carries NAMES. There is no value to publish - the
// issuer has none until a wallet sends one - and a member carrying one
// would be a different message entirely.
func TestHolderCommitmentsAdvertisement(t *testing.T) {
	metadata := &openid4vci.CredentialIssuerMetadataParameters{
		CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
			"nym_auth": {},
		},
	}
	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {Commitments: map[string]*model.CommitmentClaim{
				"psc": {Source: model.CommitmentSourceHolder, Subjects: []string{"id"}},
			}},
		}}},
		issuerMetadata: metadata,
	}
	require.NoError(t, client.advertiseHolderCommitments())

	raw, ok := metadata.CredentialConfigurationsSupported["nym_auth"].CredentialMetadata.Extensions[model.HolderCommitmentsMember]
	require.True(t, ok)

	var member map[string][]string
	require.NoError(t, json.Unmarshal(raw, &member))
	assert.Equal(t, map[string][]string{model.HolderCommitmentsListMember: {model.CommitmentPSC}}, member)

	hexValue, _ := testPSC()
	assert.NotContains(t, string(raw), hexValue, "names only, never a value")
}

// A scope expecting a holder commitment but not offered at all is
// refused, rather than quietly advertising nothing: the operator
// should learn it is unreachable now rather than from its absence.
func TestHolderCommitmentsAdvertisementRefusesAnUnofferedScope(t *testing.T) {
	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {Commitments: map[string]*model.CommitmentClaim{
				"psc": {Source: model.CommitmentSourceHolder, Subjects: []string{"id"}},
			}},
		}}},
		issuerMetadata: &openid4vci.CredentialIssuerMetadataParameters{
			CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{},
		},
	}
	assert.ErrorContains(t, client.advertiseHolderCommitments(), "not an offered credential configuration")
}

// A scope with no holder-supplied commitment is untouched.
func TestHolderCommitmentsAdvertisementSkipsIssuerDerivedScopes(t *testing.T) {
	metadata := &openid4vci.CredentialIssuerMetadataParameters{
		CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{"nym_auth": {}},
	}
	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {Commitments: map[string]*model.CommitmentClaim{
				"ssc": {Seed: "primary", Subjects: []string{"id"}},
			}},
		}}},
		issuerMetadata: metadata,
	}
	require.NoError(t, client.advertiseHolderCommitments())
	assert.Nil(t, metadata.CredentialConfigurationsSupported["nym_auth"].CredentialMetadata)
}
