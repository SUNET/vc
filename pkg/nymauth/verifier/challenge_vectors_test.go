package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// challengeVectors is test-vectors/nymauth/challenge-vectors.json, shared
// byte-for-byte between zk-cred-longfellow and zk-cred-vega.
type challengeVectors struct {
	Version       int `json:"version"`
	MinNonceChars int `json:"min_nonce_chars"`
	Derive        []struct {
		Name                 string  `json:"name"`
		Origin               string  `json:"origin"`
		Nonce                string  `json:"nonce"`
		DocType              string  `json:"doc_type"`
		JWKThumbprintHex     *string `json:"jwk_thumbprint_hex"`
		SessionTranscriptHex string  `json:"session_transcript_hex"`
		ChallengeDigestHex   string  `json:"challenge_digest_hex"`
	} `json:"derive"`
	Digest []struct {
		Name                 string `json:"name"`
		SessionTranscriptHex string `json:"session_transcript_hex"`
		DocType              string `json:"doc_type"`
		ChallengeDigestHex   string `json:"challenge_digest_hex"`
	} `json:"digest"`
	Rejects []struct {
		Name                 string  `json:"name"`
		Op                   string  `json:"op"`
		Origin               string  `json:"origin"`
		Nonce                string  `json:"nonce"`
		DocType              string  `json:"doc_type"`
		JWKThumbprintHex     *string `json:"jwk_thumbprint_hex"`
		SessionTranscriptHex string  `json:"session_transcript_hex"`
	} `json:"rejects"`
}

// The vendored copy must be the one both provers use.
//
// These vectors are what tells us this verifier and the two native
// provers agree about what a presentation is bound to. A local edit -
// or a stale copy after the upstream file moves - would turn that
// cross-implementation check into a self-consistency check that passes
// while the verifier and the provers disagree.
const challengeVectorsSHA256 = "a0984c6c99ca9a2c761b37a7cc86bf2ae2c9ddbf18e04fb5e6469d3c552c41a8"

func loadChallengeVectors(t *testing.T) challengeVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/challenge-vectors.json")
	require.NoError(t, err)

	sum := sha256.Sum256(raw)
	require.Equal(t, challengeVectorsSHA256, hex.EncodeToString(sum[:]),
		"the vendored vectors differ from the shared file; re-vendor rather than edit, or this stops checking agreement with the provers")

	var v challengeVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Derive)
	require.NotEmpty(t, v.Digest)
	require.NotEmpty(t, v.Rejects)
	return v
}

// The transcript and e2 this verifier computes must be the bytes the
// provers compute. Not "a valid CBOR encoding" - the same bytes.
func TestChallengeMatchesTheSharedVectors(t *testing.T) {
	vectors := loadChallengeVectors(t)

	require.Equal(t, MinNonceChars, vectors.MinNonceChars,
		"the nonce floor is part of the shared contract, not a local choice")

	for _, tc := range vectors.Derive {
		t.Run("derive: "+tc.Name, func(t *testing.T) {
			var thumbprint []byte
			if tc.JWKThumbprintHex != nil {
				decoded, err := hex.DecodeString(*tc.JWKThumbprintHex)
				require.NoError(t, err)
				thumbprint = decoded
			}

			transcript, err := MdocSessionTranscript(tc.Origin, tc.Nonce, thumbprint)
			require.NoError(t, err)
			assert.Equal(t, tc.SessionTranscriptHex, hex.EncodeToString(transcript),
				"the session transcript must be the bytes the provers bind to")

			e2, err := MdocE2(tc.Origin, tc.Nonce, tc.DocType, thumbprint)
			require.NoError(t, err)
			assert.Equal(t, tc.ChallengeDigestHex, hex.EncodeToString(e2[:]),
				"e2 must be the digest the provers prove against")
		})
	}

	for _, tc := range vectors.Digest {
		t.Run("digest: "+tc.Name, func(t *testing.T) {
			transcript, err := hex.DecodeString(tc.SessionTranscriptHex)
			require.NoError(t, err)

			digest, err := MdocChallengeDigest(transcript, tc.DocType)
			require.NoError(t, err)
			assert.Equal(t, tc.ChallengeDigestHex, hex.EncodeToString(digest[:]))
		})
	}
}

// There is NO minimum length on the session transcript here.
//
// Vega accepts a short one - the shared digest vector's transcript is 12
// bytes, from the Kotlin fixture - while Longfellow's core API requires
// its transcript_seed to be 32..65536 bytes. That floor is LONGFELLOW'S,
// not this package's, and real DC API SessionTranscripts are over 50
// bytes, so it only bites on fixtures. Adding the floor here would look
// like hardening and would instead refuse an input one of the two
// backends accepts, before either backend is consulted.
func TestNoMinimumTranscriptLength(t *testing.T) {
	vectors := loadChallengeVectors(t)

	shortest := 0
	for _, tc := range vectors.Digest {
		transcript, err := hex.DecodeString(tc.SessionTranscriptHex)
		require.NoError(t, err)
		if shortest == 0 || len(transcript) < shortest {
			shortest = len(transcript)
		}
		_, err = MdocChallengeDigest(transcript, tc.DocType)
		require.NoErrorf(t, err, "a %d-byte transcript is accepted by Vega and must not be refused here", len(transcript))
	}
	assert.Less(t, shortest, 32,
		"the vectors must still exercise a transcript shorter than Longfellow's own floor, or this guard proves nothing")
}

// Every input the provers refuse, this verifier must refuse too.
//
// Accepting one would build a challenge no prover reproduces, and the
// resulting failure reads as a bad proof rather than as the malformed
// request it is - which is the hardest kind of mismatch to find, because
// the holder is blamed for it.
func TestChallengeRefusesWhatTheProversRefuse(t *testing.T) {
	vectors := loadChallengeVectors(t)

	for _, tc := range vectors.Rejects {
		t.Run(tc.Op+": "+tc.Name, func(t *testing.T) {
			switch tc.Op {
			case "derive":
				var thumbprint []byte
				if tc.JWKThumbprintHex != nil {
					decoded, err := hex.DecodeString(*tc.JWKThumbprintHex)
					require.NoError(t, err)
					thumbprint = decoded
				}
				_, err := MdocE2(tc.Origin, tc.Nonce, tc.DocType, thumbprint)
				assert.Error(t, err, "the provers refuse this input")
			case "digest":
				transcript, err := hex.DecodeString(tc.SessionTranscriptHex)
				require.NoError(t, err)
				_, err = MdocChallengeDigest(transcript, tc.DocType)
				assert.Error(t, err, "the provers refuse this transcript")
			default:
				t.Fatalf("unknown reject op %q; this test is not covering it", tc.Op)
			}
		})
	}
}

// A transcript whose CONTENTS are ill-formed is refused, not only one
// whose shape is.
//
// cbor.RawMessage is bytes - the shape decode never looks inside an
// item - so a text string holding invalid UTF-8 passed every check
// and hashed cleanly into a challenge no prover reproduces. The
// mismatch then surfaces as a bad proof rather than as the malformed
// input it is, which is the failure this whole function exists to
// prevent.
func TestChallengeRefusesAnIllFormedTranscript(t *testing.T) {
	for name, encoded := range map[string]string{
		// [null, null, "<three invalid UTF-8 bytes>"]
		"invalid UTF-8 in a text string": "83f6f663fffefd",
		// [null, null, true] with true spelled as the two-byte simple
		// value 0xf8 0x15 rather than the canonical 0xf5.
		"a non-canonical simple value": "83f6f6f815",
		// [null, null, simple(0)] spelled with two bytes.
		"a two-byte simple value under 24": "83f6f6f800",
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := hex.DecodeString(encoded)
			require.NoError(t, err)

			_, err = MdocChallengeDigest(raw, "eu.europa.ec.eudi.nym_auth.1")
			assert.Error(t, err, "an ill-formed transcript must be refused, not hashed")
		})
	}
}
