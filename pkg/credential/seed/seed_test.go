package seed

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSecret is 32 bytes of nothing in particular. Only its length matters
// to anything here; the derived values are compared against each other.
var testSecret = bytes.Repeat([]byte("s"), MinSecretBytes)

func mustDeriver(t *testing.T) *Deriver {
	t.Helper()
	d, err := NewDeriver(testSecret, 0)
	require.NoError(t, err)
	return d
}

// The commitment is the only value in this package with a published
// vector: the nym_auth circuit specification's seed/ssc pair. If Commit
// ever disagrees with it, every credential this issuer writes is one no
// circuit can open.
func TestCommitMatchesThePublishedVector(t *testing.T) {
	seedValue, err := hex.DecodeString("4a8f9c1d2e3f4a5b6c7d8e9f0a1b2c3d")
	require.NoError(t, err)
	require.Len(t, seedValue, DefaultSeedBytes)

	commitment, err := Commit(CommitSHA256, seedValue)
	require.NoError(t, err)
	assert.Equal(t,
		"d424c7068cf26ed1a2c899d095f18b390f2f63897d704ed08c410a9368c345ae",
		hex.EncodeToString(commitment))

	// An unnamed function is the registered one, so a configuration that
	// omits it is not a configuration that writes a different commitment.
	defaulted, err := Commit("", seedValue)
	require.NoError(t, err)
	assert.Equal(t, commitment, defaulted)
}

// An unknown digest must not fall back. A commitment written under the
// wrong function is one nothing can ever open, and it is signed before
// anyone finds out.
func TestCommitRefusesAnUnknownFunction(t *testing.T) {
	_, err := Commit("sha3-256", bytes.Repeat([]byte("x"), DefaultSeedBytes))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown commitment function")

	_, err = CommitmentBytes("sha3-256")
	assert.Error(t, err, "and the length of a function that does not exist is not 32")

	n, err := CommitmentBytes(CommitSHA256)
	require.NoError(t, err)
	assert.Equal(t, 32, n)
}

// Golden vectors, pinning the derivation to fixed bytes.
//
// Everything else in this file compares Seed against Seed, which proves
// the derivation is consistent with ITSELF and nothing more: changing the
// label, the field order, the length-prefix width, the hash or the HKDF
// parameters would leave every one of those tests passing while giving
// every subject a new seed - and therefore a new pseudonym - with no copy
// of the old ones anywhere, because nothing is stored.
//
// These values were computed from the construction in Deriver.Seed's doc
// comment by a separate implementation, not captured from this one. If
// this test fails, the question is not whether the new output is also
// fine; it is whether every credential already issued has just been
// invalidated.
func TestDerivationGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		seedBytes  int
		context    string
		subject    string
		seed       string
		commitment string
	}{
		{
			name:       "the default length, no context",
			seedBytes:  0, // DefaultSeedBytes
			subject:    "198001011234",
			seed:       "19304fa467cdcfd8ee8ccad8524fbb6a",
			commitment: "5914935f1d59f0ed167cf4cb4a260fb5169d782c9cf65d16df5dd204d9bda37f",
		},
		{
			name:       "a context, which must change everything",
			seedBytes:  0,
			context:    "population-a",
			subject:    "198001011234",
			seed:       "0fad2375d7ad6975b276e46b9ea900e9",
			commitment: "ef4a0313a2c1dcbc7692f827f5688cc0d79cb28da25034c1917e476e9af5ae86",
		},
		{
			name:       "a longer seed, which is a different seed and not a longer one",
			seedBytes:  32,
			subject:    "198001011234",
			seed:       "18e8d4324deeed0a146c2697aef6f961399546ec0f8f6287859e94cfa0703d2b",
			commitment: "7fb47c6a048ab56c3f8ef2fa0e60a020a041e29392766be2e9c2b7c39ddbaa49",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDeriver(testSecret, tc.seedBytes)
			require.NoError(t, err)

			got, err := d.Seed(t.Context(), tc.subject, tc.context)
			require.NoError(t, err)
			assert.Equal(t, tc.seed, hex.EncodeToString(got),
				"the derivation has changed; every seed this deployment ever issued over is now different")

			commitment, err := Commit(CommitSHA256, got)
			require.NoError(t, err)
			assert.Equal(t, tc.commitment, hex.EncodeToString(commitment))
		})
	}
}

// One subject, one seed - the property the whole mechanism rests on. A
// seed that varied per call, per credential type or per format would make
// a pseudonym unrepeatable and remapping impossible.
func TestSeedIsStablePerSubject(t *testing.T) {
	d := mustDeriver(t)

	first, err := d.Seed(t.Context(), "subject-1", "")
	require.NoError(t, err)
	require.Len(t, first, DefaultSeedBytes)

	for range 5 {
		again, err := d.Seed(t.Context(), "subject-1", "")
		require.NoError(t, err)
		assert.Equal(t, first, again)
	}

	// A second Deriver over the same secret is the same deployment after a
	// restart, and must agree.
	other, err := NewDeriver(testSecret, 0)
	require.NoError(t, err)
	restarted, err := other.Seed(t.Context(), "subject-1", "")
	require.NoError(t, err)
	assert.Equal(t, first, restarted)
}

// Distinctness across every input that is supposed to separate seeds, and
// across none that are not.
func TestSeedSeparatesWhatItShould(t *testing.T) {
	d := mustDeriver(t)
	seen := map[string]string{}

	record := func(label, subject, context_ string) {
		t.Helper()
		s, err := d.Seed(t.Context(), subject, context_)
		require.NoError(t, err)
		key := hex.EncodeToString(s)
		if prev, clash := seen[key]; clash {
			t.Fatalf("%s and %s derive the same seed", prev, label)
		}
		seen[key] = label
	}

	record("subject-1", "subject-1", "")
	record("subject-2", "subject-2", "")
	record("subject-1 in context a", "subject-1", "a")
	record("subject-1 in context b", "subject-1", "b")

	// A different secret is a different deployment.
	otherSecret, err := NewDeriver(bytes.Repeat([]byte("t"), MinSecretBytes), 0)
	require.NoError(t, err)
	fromOther, err := otherSecret.Seed(t.Context(), "subject-1", "")
	require.NoError(t, err)
	assert.NotContains(t, seen, hex.EncodeToString(fromOther),
		"a different secret must give unrelated seeds")
}

// The context and the subject are length-prefixed rather than joined, so
// no split of the same characters can collide. Joined by a separator,
// ("a", "b.c") and ("a.b", "c") would be one derivation and two different
// people would share a seed.
func TestContextAndSubjectCannotBeConfused(t *testing.T) {
	d := mustDeriver(t)

	left, err := d.Seed(t.Context(), "b.c", "a")
	require.NoError(t, err)
	right, err := d.Seed(t.Context(), "c", "a.b")
	require.NoError(t, err)

	assert.NotEqual(t, left, right,
		"two different (context, subject) pairs must not derive one seed")
}

// An empty subject identifier is the case where a deployment's identity
// resolution has failed. Deriving over "" would give every such subject
// one shared seed, and therefore one shared pseudonym.
func TestSeedRefusesAnEmptySubject(t *testing.T) {
	d := mustDeriver(t)
	_, err := d.Seed(t.Context(), "", "")
	require.ErrorIs(t, err, ErrNoSubject)
}

func TestNewDeriverRefusesAnUnusableSecret(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secret []byte
	}{
		{name: "empty", secret: nil},
		{name: "one byte short", secret: bytes.Repeat([]byte("s"), MinSecretBytes-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDeriver(tc.secret, 0)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "shorter than")
			assert.NotContains(t, err.Error(), fmt.Sprint(len(tc.secret)),
				"the error must not report the secret's length")
		})
	}
}

func TestNewDeriverSeedLength(t *testing.T) {
	d, err := NewDeriver(testSecret, 0)
	require.NoError(t, err)
	assert.Equal(t, DefaultSeedBytes, d.SeedBytes(), "0 means the default")

	d32, err := NewDeriver(testSecret, 32)
	require.NoError(t, err)
	s, err := d32.Seed(t.Context(), "subject-1", "")
	require.NoError(t, err)
	assert.Len(t, s, 32)

	// A longer seed is a different seed, not the short one extended.
	//
	// HKDF expand is a stream, so without the length in the derivation
	// context the 32-byte seed would literally begin with the 16-byte one.
	// Not a weakness, but a derivation whose output is a prefix of another
	// derivation's is a trap for whoever reads this next.
	short, err := mustDeriver(t).Seed(t.Context(), "subject-1", "")
	require.NoError(t, err)
	assert.NotEqual(t, short, s[:DefaultSeedBytes],
		"the declared seed length must be part of the derivation, not just its output size")

	for _, bad := range []int{-1, MaxSeedBytes + 1} {
		_, err := NewDeriver(testSecret, bad)
		assert.Error(t, err, "seed length %d must be refused", bad)
	}
}

// The secret is copied in, so a caller reusing or zeroing its buffer
// cannot silently change every subject's seed afterwards.
func TestDeriverOwnsItsSecret(t *testing.T) {
	buf := bytes.Repeat([]byte("s"), MinSecretBytes)
	d, err := NewDeriver(buf, 0)
	require.NoError(t, err)

	before, err := d.Seed(t.Context(), "subject-1", "")
	require.NoError(t, err)

	for i := range buf {
		buf[i] = 0
	}

	after, err := d.Seed(t.Context(), "subject-1", "")
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

// Nothing on a Deriver may print the secret, under ANY verb.
//
// String and GoString are consulted only for the string-capable verbs.
// A numeric one - %d on an enclosing struct somebody logged - skips both
// and falls back to reflection, which walks in and prints the secret as
// decimal bytes. That was the behaviour here before Format existed, so
// this enumerates the verb table rather than the verbs that came to mind.
func TestDeriverDoesNotPrintItsSecret(t *testing.T) {
	d := mustDeriver(t)
	secretHex := hex.EncodeToString(testSecret)
	// Go renders a []byte differently per verb, so the decimal spelling
	// has to be checked alongside the raw bytes and the hex.
	decimal := strings.Trim(strings.Join(strings.Fields(fmt.Sprint([]byte(testSecret))), " "), "[]")

	// Every verb fmt defines for a composite operand, not a chosen few.
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%o", "%O", "%b", "%c", "%U", "%e", "%f", "%g", "%t", "%p"}

	render := map[string]string{}
	for _, verb := range verbs {
		render[verb] = fmt.Sprintf(verb, []any{d}...)
		// The case that actually happens: a struct holding one, logged.
		render[verb+" (enclosing struct)"] = fmt.Sprintf(verb, []any{struct{ D *Deriver }{d}}...)
	}

	for verb, rendered := range render {
		assert.NotContains(t, rendered, string(testSecret), "verb %s leaks the raw secret", verb)
		assert.NotContains(t, rendered, secretHex, "verb %s leaks the secret as hex", verb)
		assert.NotContains(t, rendered, decimal, "verb %s leaks the secret as a byte slice", verb)
	}

	// And the redaction is actually rendered, so the checks above are not
	// passing on an empty string.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d"} {
		assert.Contains(t, render[verb], "redacted", "verb %s must render the redaction", verb)
	}
}

// Deriver satisfies Source, which is what lets a stored implementation
// replace it later without anything above changing.
var _ Source = (*Deriver)(nil)
