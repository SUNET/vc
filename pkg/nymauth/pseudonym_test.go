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
	a, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "rp.example")
	require.NoError(t, err)
	b, err := KnownOffenderMatching(ConfigKnownOffenderMatchingPSC, testSeed, "rp.example")
	require.NoError(t, err)
	c, err := AccountRecovery(testSeed, "rp.example", "account-1")
	require.NoError(t, err)

	assert.NotEqual(t, a, b)
	assert.NotEqual(t, a, c)
	assert.NotEqual(t, b, c)
}

// Known-offender matching only works if one Verifier always sees the same
// pseudonym for one person, and different Verifiers never do.
func TestKnownOffenderMatchingPerVerifier(t *testing.T) {
	first, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "rp.example")
	require.NoError(t, err)
	again, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "rp.example")
	require.NoError(t, err)
	assert.Equal(t, first, again)

	other, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "other.example")
	require.NoError(t, err)
	assert.NotEqual(t, first, other)

	// Two bare identifiers that differ at all are unrelated identities.
	// (This used to assert that the rulebook's two PREFIXED forms of one
	// Relying Party were unrelated; the prefix is no longer hashed, so
	// what is left is the plain property that different ids differ.)
	nearby, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "rp.example.semantic")
	require.NoError(t, err)
	assert.NotEqual(t, first, nearby)
}

// Account recovery is per verifier AND per context, which is what makes
// it per account rather than per person.
func TestAccountRecoveryIsPerContext(t *testing.T) {
	one, err := AccountRecovery(testSeed, "rp.example", "account-1")
	require.NoError(t, err)
	two, err := AccountRecovery(testSeed, "rp.example", "account-2")
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

	_, err = KnownOffenderMatching(ConfigAccountRecoverySSC, testSeed, "rp.example")
	assert.Error(t, err, "account recovery has a different verifier_input and must not come through here")
	_, err = KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "")
	assert.Error(t, err)

	// The rulebook bounds verifier_context at 1-64 bytes.
	_, err = AccountRecovery(testSeed, "rp.example", "")
	assert.Error(t, err)
	_, err = AccountRecovery(testSeed, "rp.example", string(bytes.Repeat([]byte("c"), 65)))
	assert.Error(t, err)
	_, err = AccountRecovery(testSeed, "rp.example", string(bytes.Repeat([]byte("c"), 64)))
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

	_, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, bytes.Repeat([]byte{7}, 32), "rp.example")
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
		// Values that name no Verifier at all. The prefixed form is
		// no longer among them: v0.4 hashes it, and the archive's
		// reference pseudonyms are computed from it.
		"x509_san_dns:",
		"semantic_id:",
		"",
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
	// Every published form, prefix included: v0.4 hashes the
	// verifier_id exactly as published, so the only thing refused is a
	// value that names nobody.
	for _, good := range []string{
		"rp.example",
		"verifier.example",
		"semantic_id:rp.example",
		"x509_san_dns:rp.example",
		"https://rp.example/path",
		"x509_hash:abcd",
	} {
		_, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, good)
		assert.NoErrorf(t, err, "%q is a bare verifier_id", good)
	}

	// And a semantic verifier_id is hashed WHOLE: the digest is over
	// "semantic_id:rp.example", not over "rp.example".
	semantic := sha256.Sum256([]byte("semantic_id:rp.example"))
	identifierOnly := sha256.Sum256([]byte("rp.example"))
	require.NotEqual(t, semantic, identifierOnly)
	gotSemantic, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "semantic_id:rp.example")
	require.NoError(t, err)
	wantSemantic, err := Pseudonym(ConfigKnownOffenderMatchingSSC, testSeed, nullInput, semantic[:])
	require.NoError(t, err)
	assert.Equal(t, wantSemantic, gotSemantic)

	// The two spellings are different verifier_ids, and both now
	// derive - which is the point of hashing exactly as published.
	fromBare, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "verifier.example")
	require.NoError(t, err)
	want, err := Pseudonym(ConfigKnownOffenderMatchingSSC, testSeed, nullInput, bare[:])
	require.NoError(t, err)
	assert.Equal(t, want, fromBare,
		"verifier_input must be SHA256 of the bare id, with nothing prepended")
}
