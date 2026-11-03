package verifier

import (
	"bytes"
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

	// The OpenID4VP redirect handover (appendix B.2.6.1), added
	// alongside the DC API one rather than replacing it: a
	// presentation arrives over one channel or the other, and the two
	// bind to different transcripts.
	DeriveRedirect []struct {
		Name                 string `json:"name"`
		ClientID             string `json:"client_id"`
		Nonce                string `json:"nonce"`
		ResponseURI          string `json:"response_uri"`
		DocType              string `json:"doc_type"`
		JWKThumbprintHex     string `json:"jwk_thumbprint_hex"`
		HandoverInfoHex      string `json:"handover_info_hex"`
		SessionTranscriptHex string `json:"session_transcript_hex"`
		ChallengeDigestHex   string `json:"challenge_digest_hex"`
	} `json:"derive_redirect"`
	RejectsRedirect []struct {
		Name             string  `json:"name"`
		Op               string  `json:"op"`
		ClientID         string  `json:"client_id"`
		Nonce            string  `json:"nonce"`
		ResponseURI      string  `json:"response_uri"`
		DocType          string  `json:"doc_type"`
		JWKThumbprintHex *string `json:"jwk_thumbprint_hex"`
		Reason           string  `json:"reason"`
	} `json:"rejects_redirect"`
}

// The vendored copy must be the one both provers use.
//
// These vectors are what tells us this verifier and the two native
// provers agree about what a presentation is bound to. A local edit -
// or a stale copy after the upstream file moves - would turn that
// cross-implementation check into a self-consistency check that passes
// while the verifier and the provers disagree.
const challengeVectorsSHA256 = "611f6ba601034c37cefddb91422bcafd648c93b181e5eab730305ff46101cb6a"

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
	require.NotEmpty(t, v.DeriveRedirect)
	require.NotEmpty(t, v.RejectsRedirect)
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

// The redirect handover's transcript and e2 must be the bytes the
// provers compute, exactly as the DC API handover's are.
//
// Every derive_redirect vector, including the OpenID4VP 1.0 B.2.6.1
// non-normative example - which is the one case where the expected
// bytes come from the specification rather than from a sibling
// implementation, so agreeing with it is agreeing with the standard
// and not merely with ourselves.
func TestRedirectChallengeMatchesTheSharedVectors(t *testing.T) {
	vectors := loadChallengeVectors(t)

	for _, tc := range vectors.DeriveRedirect {
		t.Run("derive_redirect: "+tc.Name, func(t *testing.T) {
			thumbprint, err := hex.DecodeString(tc.JWKThumbprintHex)
			require.NoError(t, err)

			transcript, err := MdocSessionTranscriptRedirect(tc.ClientID, tc.Nonce, tc.ResponseURI, thumbprint)
			require.NoError(t, err)
			assert.Equal(t, tc.SessionTranscriptHex, hex.EncodeToString(transcript),
				"the session transcript must be the bytes the provers bind to")

			e2, err := MdocE2Redirect(tc.ClientID, tc.Nonce, tc.ResponseURI, tc.DocType, thumbprint)
			require.NoError(t, err)
			assert.Equal(t, tc.ChallengeDigestHex, hex.EncodeToString(e2[:]),
				"e2 must be the digest the provers prove against")
		})
	}
}

// Every input the provers refuse for the redirect handover, this
// refuses too.
//
// A verifier that accepted one of these would build a transcript no
// prover reproduces, and the mismatch would surface as a failed proof
// - sending whoever debugs it to look at the circuit rather than at
// the malformed input.
func TestRedirectChallengeRefusesWhatTheProversRefuse(t *testing.T) {
	vectors := loadChallengeVectors(t)

	for _, tc := range vectors.RejectsRedirect {
		t.Run("rejects_redirect: "+tc.Name, func(t *testing.T) {
			require.Equal(t, "derive_redirect", tc.Op,
				"every rejects_redirect case is a derive_redirect case; a new op needs its own arm here, not a silent skip")

			var thumbprint []byte
			if tc.JWKThumbprintHex != nil {
				decoded, err := hex.DecodeString(*tc.JWKThumbprintHex)
				require.NoError(t, err)
				thumbprint = decoded
			}

			_, err := MdocSessionTranscriptRedirect(tc.ClientID, tc.Nonce, tc.ResponseURI, thumbprint)
			if err == nil {
				// docType is not an input to the transcript, so a
				// vector that rejects on it rejects at the digest
				// step instead - which is the same refusal, one
				// function later.
				_, err = MdocE2Redirect(tc.ClientID, tc.Nonce, tc.ResponseURI, tc.DocType, thumbprint)
			}
			require.Error(t, err, "reason: %s", tc.Reason)
		})
	}
}

// The two handovers are different structures, and the same session
// must not produce the same transcript through both.
//
// This is the failure the channel selection exists to prevent: a
// wallet built one of them, and verifying against the other is an
// opaque proof failure rather than a legible wiring error.
func TestTheTwoHandoversAreNotInterchangeable(t *testing.T) {
	const (
		nonce       = "pOA0oqEAhLnqug2r7Ve4tQ"
		responseURI = "https://verifier.example/verification/direct_post"
	)
	thumbprint := bytes.Repeat([]byte{0x11}, 32)

	redirect, err := MdocSessionTranscriptRedirect("x509_san_dns:verifier.example", nonce, responseURI, thumbprint)
	require.NoError(t, err)
	dcAPI, err := MdocSessionTranscript("https://verifier.example", nonce, thumbprint)
	require.NoError(t, err)

	assert.NotEqual(t, hex.EncodeToString(dcAPI), hex.EncodeToString(redirect),
		"two handovers, two transcripts")
	assert.Contains(t, hex.EncodeToString(redirect), hex.EncodeToString([]byte("OpenID4VPHandover")))
	assert.Contains(t, hex.EncodeToString(dcAPI), hex.EncodeToString([]byte("OpenID4VPDCAPIHandover")))
}

// A nil thumbprint is accepted by the DC API handover and refused by
// the redirect one.
//
// Not an inconsistency: over a redirect the response is always
// encrypted, so there is always a reader key, and a missing
// thumbprint means a request that should never have been sent. The
// DC API handover keeps null for an unencrypted response. Both are in
// the shared vectors, on their own sides.
func TestRedirectRequiresTheThumbprintThatDCAPIMayOmit(t *testing.T) {
	const nonce = "pOA0oqEAhLnqug2r7Ve4tQ"

	_, err := MdocSessionTranscript("https://verifier.example", nonce, nil)
	require.NoError(t, err, "the DC API handover takes null for an unencrypted response")

	_, err = MdocSessionTranscriptRedirect(
		"x509_san_dns:verifier.example", nonce, "https://verifier.example/response", nil)
	require.Error(t, err, "a redirect presentation is always encrypted, so it always has a thumbprint")
	assert.Contains(t, err.Error(), "always encrypted")
}
