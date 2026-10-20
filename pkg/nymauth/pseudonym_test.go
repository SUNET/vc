package nymauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSeed = func() []byte {
	s, _ := hex.DecodeString("4a8f9c1d2e3f4a5b6c7d8e9f0a1b2c3d")
	return s
}()

// The construction, spelled out independently of the implementation:
// SHA256(DST || seed || prover_input || verifier_input), DST =
// "nym_auth/v1/<config>".
func TestPseudonymIsTheSpecifiedConstruction(t *testing.T) {
	prover := bytes.Repeat([]byte{1}, 32)
	verifier := bytes.Repeat([]byte{2}, 32)

	got, err := Pseudonym("some-config", testSeed, prover, verifier)
	require.NoError(t, err)

	want := sha256.Sum256(append(append(append(
		[]byte("nym_auth/v1/some-config"), testSeed...), prover...), verifier...))
	assert.Equal(t, want[:], got)
	assert.Len(t, got, 32)
}

// The DST carries the configuration name, so one subject's pseudonym
// under two configurations is unrelated - which is what stops an account
// recovery pseudonym being usable for offender matching.
func TestConfigurationSeparatesPseudonyms(t *testing.T) {
	a, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "x509_san_dns:rp.example")
	require.NoError(t, err)
	b, err := KnownOffenderMatching(ConfigKnownOffenderMatchingPSC, testSeed, "x509_san_dns:rp.example")
	require.NoError(t, err)
	c, err := AccountRecovery(testSeed, "x509_san_dns:rp.example", "account-1")
	require.NoError(t, err)

	assert.NotEqual(t, a, b)
	assert.NotEqual(t, a, c)
	assert.NotEqual(t, b, c)
}

// Known-offender matching only works if one Verifier always sees the same
// pseudonym for one person, and different Verifiers never do.
func TestKnownOffenderMatchingPerVerifier(t *testing.T) {
	first, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "x509_san_dns:rp.example")
	require.NoError(t, err)
	again, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "x509_san_dns:rp.example")
	require.NoError(t, err)
	assert.Equal(t, first, again)

	other, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "x509_san_dns:other.example")
	require.NoError(t, err)
	assert.NotEqual(t, first, other)

	// Two bare identifiers that differ at all are unrelated identities.
	// (This used to assert that the rulebook's two PREFIXED forms of one
	// Relying Party were unrelated; the prefix is no longer hashed, so
	// what is left is the plain property that different ids differ.)
	nearby, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "x509_san_dns:rp.example.semantic")
	require.NoError(t, err)
	assert.NotEqual(t, first, nearby)
}

// Account recovery is per verifier AND per context, which is what makes
// it per account rather than per person.
func TestAccountRecoveryIsPerContext(t *testing.T) {
	one, err := AccountRecovery(testSeed, "x509_san_dns:rp.example", "account-1")
	require.NoError(t, err)
	two, err := AccountRecovery(testSeed, "x509_san_dns:rp.example", "account-2")
	require.NoError(t, err)
	assert.NotEqual(t, one, two)
}

func TestInputValidation(t *testing.T) {
	good := bytes.Repeat([]byte{0}, 32)

	_, err := Pseudonym("", testSeed, good, good)
	assert.Error(t, err)
	_, err = Pseudonym("c", nil, good, good)
	assert.Error(t, err)

	// A short input would shift everything after it in the concatenation
	// and silently produce a different pseudonym.
	_, err = Pseudonym("c", testSeed, good[:31], good)
	assert.Error(t, err, "a prover_input of the wrong length must be refused, not padded")
	_, err = Pseudonym("c", testSeed, good, good[:31])
	assert.Error(t, err)

	_, err = KnownOffenderMatching(ConfigAccountRecoverySSC, testSeed, "x509_san_dns:rp.example")
	assert.Error(t, err, "account recovery has a different verifier_input and must not come through here")
	_, err = KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "")
	assert.Error(t, err)

	// The rulebook bounds verifier_context at 1-64 bytes.
	_, err = AccountRecovery(testSeed, "x509_san_dns:rp.example", "")
	assert.Error(t, err)
	_, err = AccountRecovery(testSeed, "x509_san_dns:rp.example", string(bytes.Repeat([]byte("c"), 65)))
	assert.Error(t, err)
	_, err = AccountRecovery(testSeed, "x509_san_dns:rp.example", string(bytes.Repeat([]byte("c"), 64)))
	assert.NoError(t, err)

	_, err = UserManagedXsite(testSeed, "")
	assert.Error(t, err)
}

// The cross-site configuration goes to every Verifier the same, which is
// the whole of what it offers and the whole of what it costs.
func TestUserManagedXsiteIgnoresTheVerifier(t *testing.T) {
	a, err := UserManagedXsite(testSeed, "my linking value")
	require.NoError(t, err)
	b, err := UserManagedXsite(testSeed, "my linking value")
	require.NoError(t, err)
	assert.Equal(t, a, b)

	c, err := UserManagedXsite(testSeed, "a different linking value")
	require.NoError(t, err)
	assert.NotEqual(t, a, c)
}

// The rulebook fixes both seeds at 16 bytes. A generic seed source
// configured with a different seed_bytes would otherwise hash a
// concatenation shifted against what the circuit computes - and the
// result is 32 bytes either way, so nothing downstream could tell.
func TestSeedLengthIsFixedByTheRulebook(t *testing.T) {
	good := bytes.Repeat([]byte{0}, 32)

	for _, n := range []int{1, 15, 17, 32} {
		_, err := Pseudonym("c", bytes.Repeat([]byte{7}, n), good, good)
		assert.Error(t, err, "a %d-byte seed must be refused", n)
	}

	_, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, bytes.Repeat([]byte{7}, 32), "x509_san_dns:rp.example")
	assert.Error(t, err, "the configuration helpers must refuse it too, not just Pseudonym")

	_, err = Pseudonym("c", bytes.Repeat([]byte{7}, SeedBytes), good, good)
	assert.NoError(t, err)
}

// The rulebook defines exactly two verifier_id forms. Hashing anything
// else succeeds and returns a 32-byte value indistinguishable from a
// correct pseudonym - so a remapping loop comparing against what a
// Verifier actually reported would never match, and the operator would
// conclude the subject is not the one they are looking for. A wrong
// answer, not an error.
// The hashed verifier input is the BARE verifier_id.
//
// This test used to assert the opposite - that a prefixed Client
// Identifier was the form to hash - and it was wrong. The rulebook
// states the bare form with worked digests and marks the prefixed one
// MUST NOT; verifier_id_type is agreed out of band and is not hashed.
// Hashing the prefix produces a 32-byte value indistinguishable from a
// correct pseudonym that no Verifier will ever report, so a remapping
// loop would simply never match and an operator would conclude the
// subject is innocent.
func TestVerifierInputIsThePrefixedVerifierID(t *testing.T) {
	// The rulebook's worked digests, recomputed here rather than
	// copied as opaque constants: if either moves, this says which.
	bare := sha256.Sum256([]byte("verifier.example"))
	prefixed := sha256.Sum256([]byte("x509_san_dns:verifier.example"))
	require.Equal(t, "6eae85a0", hex.EncodeToString(prefixed[:])[:8],
		"rulebook v0.4's MUST digest for the prefixed verifier_id, and the archive's own verifier_input")
	require.Equal(t, "be6a6400", hex.EncodeToString(bare[:])[:8],
		"and the bare DNS name, which v0.4 says is NOT a verifier_id")

	for _, bad := range []string{
		// A marker with nothing after it names no Verifier.
		"x509_san_dns:",
		"semantic_id:",
		"",
		// And rulebook v0.4 defines exactly two forms, so a value
		// starting with neither is refused rather than hashed. The
		// bare DNS name is the one that matters in practice: it was
		// the CORRECT value until 2026-10-20, so any configuration
		// written before then still carries it.
		"rp.example",
		"verifier.example",
		"sirosid-gdc-vc-verifier.fly.dev",
		"https://rp.example/path",
		"x509_hash:abcd",
		"X509_SAN_DNS:rp.example",
	} {
		_, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, bad)
		assert.Errorf(t, err, "verifier_id %q is not what the rulebook hashes", bad)

		_, err = AccountRecovery(testSeed, bad, "account-1")
		assert.Errorf(t, err, "account recovery must refuse %q too", bad)
	}

	// Bare identifiers, including ones that merely CONTAIN a colon -
	// the guard is about the Client Identifier Prefix, not about
	// punctuation.
	//
	// The two forms rulebook v0.4 defines, hashed exactly as
	// published. What follows the marker is opaque: the rulebook
	// constrains the form, not the identifier inside it.
	for _, good := range []string{
		"x509_san_dns:rp.example",
		"x509_san_dns:verifier.example",
		"x509_san_dns:a.b.c.d.e",
		"semantic_id:rp.example",
		"semantic_id:age-over-18-check",
		"semantic_id:anything at all, even with spaces",
	} {
		_, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, good)
		assert.NoErrorf(t, err, "%q is one of the two defined forms", good)
	}

	// And a semantic verifier_id is hashed WHOLE: the digest is over
	// "semantic_id:rp.example", not over "x509_san_dns:rp.example".
	semantic := sha256.Sum256([]byte("semantic_id:rp.example"))
	identifierOnly := sha256.Sum256([]byte("x509_san_dns:rp.example"))
	require.NotEqual(t, semantic, identifierOnly)
	gotSemantic, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "semantic_id:rp.example")
	require.NoError(t, err)
	wantSemantic, err := Pseudonym(ConfigKnownOffenderMatchingSSC, testSeed, nullInput, semantic[:])
	require.NoError(t, err)
	assert.Equal(t, wantSemantic, gotSemantic)

	// The pseudonym really is derived from the PREFIXED string, with
	// nothing added and nothing removed.
	fromPrefixed, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "x509_san_dns:verifier.example")
	require.NoError(t, err)
	want, err := Pseudonym(ConfigKnownOffenderMatchingSSC, testSeed, nullInput, prefixed[:])
	require.NoError(t, err)
	assert.Equal(t, want, fromPrefixed,
		"verifier_input must be SHA256 of the verifier_id exactly as published")

	// And the bare DNS name is not a verifier_id at all, so it never
	// reaches a digest - which is what stops a configuration written
	// before the reversal from silently producing wrong pseudonyms.
	_, err = KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "verifier.example")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509_san_dns:verifier.example",
		"the refusal should name the value the operator probably meant")
}
