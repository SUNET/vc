package nymauth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The corpus these cases come from used to run through the issuer's
// KnownOffenderMatching, which Credential Auxiliary Data removes. It is
// exercised directly here instead, against the function both sides call.

func TestCheckVerifierIDAcceptsTheTwoFormsV04Defines(t *testing.T) {
	// What follows the marker is opaque: the rulebook constrains the
	// form, not the identifier inside it.
	for _, good := range []string{
		"x509_san_dns:rp.example",
		"x509_san_dns:verifier.example",
		"x509_san_dns:sirosid-gdc-vc-verifier.fly.dev",
		"x509_san_dns:a.b.c.d.e",
		"semantic_id:rp.example",
		"semantic_id:age-over-18-check",
		"semantic_id:anything at all, even with spaces",
	} {
		assert.NoErrorf(t, CheckVerifierID(good), "%q is one of the two defined forms", good)
	}
}

func TestCheckVerifierIDRefusesEverythingElse(t *testing.T) {
	for _, bad := range []string{
		// A marker with nothing after it names no Verifier.
		"x509_san_dns:",
		"semantic_id:",
		"",
		// v0.4 defines exactly two forms, so a value starting with
		// neither is refused rather than hashed. The bare DNS name is
		// the one that matters in practice: it was the CORRECT value
		// until 2026-10-20, so a configuration written before then
		// still carries one.
		"rp.example",
		"verifier.example",
		"sirosid-gdc-vc-verifier.fly.dev",
		"https://rp.example/path",
		"x509_hash:abcd",
		// Case is not normalised: a third spelling is a value nobody
		// agreed the meaning of.
		"X509_SAN_DNS:rp.example",
	} {
		assert.Errorf(t, CheckVerifierID(bad), "verifier_id %q is not a form the rulebook defines", bad)
	}
}

// The refusal has to be actionable: an operator holding the pre-2026-10-20
// value should be told what to write instead, not left to infer it.
func TestCheckVerifierIDNamesTheLikelyFix(t *testing.T) {
	err := CheckVerifierID("sirosid-gdc-vc-verifier.fly.dev")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509_san_dns:sirosid-gdc-vc-verifier.fly.dev",
		"a bare DNS name should be answered with the prefixed value it probably meant")

	// And a value that is not plausibly a host gets no misleading hint.
	err = CheckVerifierID("x509_hash:abcd")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "probably")
}

// verifier_input is SHA-256 of the WHOLE verifier_id, prefix included,
// which is what makes the check above load-bearing rather than cosmetic:
// the two digests below are different pseudonym scopes entirely.
//
// Recomputed rather than copied as opaque constants: if either moves,
// this says which.
func TestTheWholeVerifierIDIsWhatGetsHashed(t *testing.T) {
	prefixed := sha256.Sum256([]byte("x509_san_dns:verifier.example"))
	bare := sha256.Sum256([]byte("verifier.example"))
	semantic := sha256.Sum256([]byte("semantic_id:rp.example"))

	assert.Equal(t, "6eae85a0", hex.EncodeToString(prefixed[:])[:8],
		"rulebook v0.4's MUST digest for the prefixed verifier_id, and the circuits archive's own verifier_input")
	assert.Equal(t, "be6a6400", hex.EncodeToString(bare[:])[:8],
		"and the bare DNS name, which v0.4 says is NOT a verifier_id")
	assert.NotEqual(t, prefixed, bare)

	// A semantic verifier_id is hashed whole too, so it scopes
	// differently from the same identifier under the other prefix.
	assert.NotEqual(t, semantic, sha256.Sum256([]byte("x509_san_dns:rp.example")))
	assert.NotEqual(t, semantic, sha256.Sum256([]byte("rp.example")))
}

func TestLooksLikeDNSName(t *testing.T) {
	for _, yes := range []string{"rp.example", "a.b.c", "x-1.example-2.org"} {
		assert.Truef(t, looksLikeDNSName(yes), "%q", yes)
	}
	for _, no := range []string{"", "nodot", "has space.example", "has/slash.example", "has:colon.example", "a..b", "ünicode.example"} {
		assert.Falsef(t, looksLikeDNSName(no), "%q", no)
	}
}
