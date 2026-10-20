package seed

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two different identifier lists must be two different keys. The
// length-prefixed encoding is what guarantees it, and these are the
// pairs that would collide under a naive join.
func TestSubjectKeyIsInjectiveOverTheOrderedList(t *testing.T) {
	lists := [][]string{
		{"ab", "c"},
		{"a", "bc"},
		{"abc"},
		{"a", "b", "c"},
		{"c", "ab"},
	}

	keys := map[string][]string{}
	for _, ids := range lists {
		key, err := SubjectKeyHex(ids)
		require.NoError(t, err)
		prev, seen := keys[key]
		require.Falsef(t, seen, "%v and %v produced one subject key", prev, ids)
		keys[key] = ids
	}
	assert.Len(t, keys, len(lists))

	// And the same list is the same key, every time: a key that moved
	// would make every stored record unreachable.
	first, err := SubjectKeyHex(lists[0])
	require.NoError(t, err)
	again, err := SubjectKeyHex([]string{"ab", "c"})
	require.NoError(t, err)
	assert.Equal(t, first, again)
}

// Order is part of the key, as it is part of the seed. Reordering the
// list is a different subject, not the same one.
func TestSubjectKeyDependsOnOrder(t *testing.T) {
	a, err := SubjectKeyHex([]string{"SE", "19800101-1234"})
	require.NoError(t, err)
	b, err := SubjectKeyHex([]string{"19800101-1234", "SE"})
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
}

// A subject key is not a seed derivation input, and must not be
// confusable with one. The labels are what separate them.
func TestSubjectKeyIsNotTheDerivationEncoding(t *testing.T) {
	ids := []string{"SE", "19800101-1234"}

	subject, err := subjectKeyInfo(ids...)
	require.NoError(t, err)
	derivation, err := derivationInfo(ids...)
	require.NoError(t, err)
	assert.NotEqual(t, derivation, subject, "the two encodings must not agree")
}

// The same refusals as Seed, for the same reason: skipping an empty
// identifier would key one subject's record under another's.
func TestSubjectKeyRefusesWhatSeedRefuses(t *testing.T) {
	_, err := SubjectKey(nil)
	assert.ErrorIs(t, err, ErrNoSubject)

	_, err = SubjectKey([]string{"a", ""})
	assert.ErrorIs(t, err, ErrNoSubject)

	tooMany := make([]string, maxDerivationFields+1)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	_, err = SubjectKey(tooMany)
	assert.ErrorContains(t, err, "exceeds the limit")

	long := make([]byte, maxDerivationField+1)
	for i := range long {
		long[i] = 'x'
	}
	_, err = SubjectKey([]string{string(long)})
	assert.ErrorContains(t, err, "would collide")
}

// Hex of exactly 32 bytes, which is what the stores hold.
func TestSubjectKeyHexIsThirtyTwoBytes(t *testing.T) {
	key, err := SubjectKeyHex([]string{"SE", "19800101-1234"})
	require.NoError(t, err)
	raw, err := hex.DecodeString(key)
	require.NoError(t, err)
	assert.Len(t, raw, SubjectKeyBytes)
}
