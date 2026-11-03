//go:build zknative

package verifier

import (
	"encoding/hex"
	"testing"

	"github.com/SUNET/vc/pkg/nymauth/verifier/zknative"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pure-Go challenge derivation in challenge.go exists so a verifier
// can build a request without linking the native library. That is only
// safe while it produces the same bytes the library does - and the
// vectors alone cannot show it, because they would still pass if both
// this package and the vectors were stale against the library.
//
// So this runs both implementations over the same inputs and compares
// them directly. It is the test that would catch the library changing
// the transcript shape under a vendored vectors file.
func TestGoChallengeDerivationMatchesTheLibrary(t *testing.T) {
	vectors := loadChallengeVectors(t)

	for _, tc := range vectors.Derive {
		t.Run(tc.Name, func(t *testing.T) {
			var thumbprint []byte
			if tc.JWKThumbprintHex != nil {
				var err error
				thumbprint, err = hex.DecodeString(*tc.JWKThumbprintHex)
				require.NoError(t, err)
			}

			goTranscript, err := MdocSessionTranscript(tc.Origin, tc.Nonce, thumbprint)
			require.NoError(t, err)
			goDigest, err := MdocChallengeDigest(goTranscript, tc.DocType)
			require.NoError(t, err)

			cTranscript, cDigest, err := zknative.DeriveChallenge(tc.Origin, tc.Nonce, tc.DocType, thumbprint)
			require.NoError(t, err)

			assert.Equal(t, hex.EncodeToString(cTranscript), hex.EncodeToString(goTranscript),
				"the session transcript this package builds must be the one the library builds")
			assert.Equal(t, hex.EncodeToString(cDigest[:]), hex.EncodeToString(goDigest[:]),
				"e2 must be the library's e2")
		})
	}
}

// Same check for a transcript already in hand, which is the path a
// verifier takes when it holds the transcript from its own session.
func TestGoChallengeDigestMatchesTheLibrary(t *testing.T) {
	vectors := loadChallengeVectors(t)

	for _, tc := range vectors.Digest {
		t.Run(tc.Name, func(t *testing.T) {
			transcript, err := hex.DecodeString(tc.SessionTranscriptHex)
			require.NoError(t, err)

			goDigest, err := MdocChallengeDigest(transcript, tc.DocType)
			require.NoError(t, err)
			cDigest, err := zknative.ChallengeDigest(transcript, tc.DocType)
			require.NoError(t, err)

			assert.Equal(t, hex.EncodeToString(cDigest[:]), hex.EncodeToString(goDigest[:]))
		})
	}
}

// verifier_input is SHA-256 of the BARE verifier_id. The library hashes
// whatever it is given, so this checks the agreed value and leaves the
// refusal of a prefixed Client Identifier - which is this package's
// rule, not the library's - to request_test.go.
func TestGoVerifierInputMatchesTheLibrary(t *testing.T) {
	const verifierID = "verifier.example"

	goInput, err := VerifierInput(verifierID)
	require.NoError(t, err)
	cInput, err := zknative.VerifierInput(verifierID)
	require.NoError(t, err)

	assert.Equal(t, hex.EncodeToString(cInput[:]), hex.EncodeToString(goInput[:]))
	assert.Equal(t, "be6a6400", hex.EncodeToString(goInput[:])[:8],
		"nym_auth_rulebook PR #7's MUST digest for the bare verifier_id")
}

// Both bindings refuse the same malformed challenge inputs. A verifier
// that accepted one the library refuses would build a challenge no
// prover reproduces and read the resulting failure as a bad proof.
func TestGoAndLibraryRefuseTheSameChallengeInputs(t *testing.T) {
	vectors := loadChallengeVectors(t)

	for _, tc := range vectors.Rejects {
		t.Run(tc.Name, func(t *testing.T) {
			var thumbprint []byte
			if tc.JWKThumbprintHex != nil {
				var err error
				thumbprint, err = hex.DecodeString(*tc.JWKThumbprintHex)
				require.NoError(t, err)
			}

			switch tc.Op {
			case "derive":
				_, goErr := MdocE2(tc.Origin, tc.Nonce, tc.DocType, thumbprint)
				_, _, cErr := zknative.DeriveChallenge(tc.Origin, tc.Nonce, tc.DocType, thumbprint)
				assert.Error(t, goErr, "this package must refuse it")
				assert.Error(t, cErr, "the library must refuse it too")
			case "digest":
				transcript, err := hex.DecodeString(tc.SessionTranscriptHex)
				require.NoError(t, err)
				_, goErr := MdocChallengeDigest(transcript, tc.DocType)
				_, cErr := zknative.ChallengeDigest(transcript, tc.DocType)
				assert.Error(t, goErr, "this package must refuse it")
				assert.Error(t, cErr, "the library must refuse it too")
			default:
				t.Fatalf("unknown reject op %q", tc.Op)
			}
		})
	}
}
