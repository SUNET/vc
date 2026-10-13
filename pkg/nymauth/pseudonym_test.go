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

	// The rulebook's two identifier forms are unrelated identities, and
	// the note saying so is a property to preserve, not to smooth over.
	semantic, err := KnownOffenderMatching(ConfigKnownOffenderMatchingSSC, testSeed, "semantic_id:rp.example")
	require.NoError(t, err)
	assert.NotEqual(t, first, semantic)
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
