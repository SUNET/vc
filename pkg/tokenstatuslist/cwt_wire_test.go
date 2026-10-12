package tokenstatuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the CWT wire format against draft-ietf-oauth-status-list.
// vc diverged from it in four places at once - the status_list and ttl claim
// labels, the StatusList member keys, and the typ header - and each
// divergence collided with something else the draft defines, so a
// conforming reader did not merely fail to understand vc's output, it
// misread it. What is written is the draft's spelling; what is read is
// either.

func generateTestCWT(t *testing.T, ttl int64) []byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cwtBytes, err := GenerateCWT(CWTConfig{
		Issuer:     "https://example.com",
		Subject:    "https://example.com/statuslists/1",
		Statuses:   []uint8{0, 1, 2, 1},
		ExpiresIn:  24 * time.Hour,
		TTL:        ttl,
		SigningKey: privateKey,
	})
	require.NoError(t, err)
	return cwtBytes
}

// TestCWTClaimLabelsMatchDraft: Section 14.3 registers status_list at 65533
// and ttl at 65534. vc wrote 65534 and 65535, which put status_list on the
// draft's ttl label and ttl on the draft's `status` label.
func TestCWTClaimLabelsMatchDraft(t *testing.T) {
	assert.Equal(t, 65533, CWTClaimStatusList)
	assert.Equal(t, 65534, CWTClaimTTL)

	claims, err := ParseCWT(generateTestCWT(t, 43200))
	require.NoError(t, err)

	assert.NotNil(t, claims[65533], "status_list must be written at the registered label")
	assert.NotNil(t, claims[65534], "ttl must be written at the registered label")
	_, occupied := claims[65535]
	assert.False(t, occupied, "65535 is the draft's `status` claim and must not be written here")

	// ttl is an unsigned integer, not the map a status_list is.
	_, ttlIsAStatusList := normalizeStatusListMap(claims[65534])
	assert.False(t, ttlIsAStatusList, "the value at 65534 must be a ttl, not a status_list")
}

// TestCWTStatusListUsesTextKeys: Section 4.3's CDDL names the StatusList
// members with text keys, and the draft's own annotated hex shows
// a2 64 62697473 ... - map(2), "bits". vc emitted integer labels 1/2/3.
func TestCWTStatusListUsesTextKeys(t *testing.T) {
	claims, err := ParseCWT(generateTestCWT(t, 0))
	require.NoError(t, err)

	sl, ok := normalizeStatusListMap(claims[CWTClaimStatusList])
	require.True(t, ok)

	assert.Contains(t, sl.text, "bits")
	assert.Contains(t, sl.text, "lst")
	assert.Empty(t, sl.ints, "no member may be written under an integer label")
}

// TestCWTStatusListClaim_ReadsLegacyLabel: a list published by an older vc
// still parses, so a deployment is not dark for the one refresh cycle it
// takes for the lists to be regenerated.
func TestCWTStatusListClaim_ReadsLegacyLabel(t *testing.T) {
	legacy := map[int]any{
		1:     "https://example.com",
		65534: map[any]any{int64(1): uint64(8), int64(2): []byte{0x01, 0x02}},
	}

	raw, ok := CWTStatusListClaim(legacy)
	require.True(t, ok, "a status_list at the old label must still be found")

	bits, lst, err := CWTStatusListMembers(raw)
	require.NoError(t, err)
	assert.Equal(t, 8, bits)
	assert.Equal(t, []byte{0x01, 0x02}, lst)
}

// TestCWTStatusListClaim_TTLIsNotMistakenForAStatusList is the reason the
// fallback can exist at all: the old status_list label is the new ttl
// label, so the two are told apart by type. A conforming token with a ttl
// and no status_list must report a missing status_list, never a malformed
// one built out of an integer.
func TestCWTStatusListClaim_TTLIsNotMistakenForAStatusList(t *testing.T) {
	_, ok := CWTStatusListClaim(map[int]any{65534: uint64(43200)})
	assert.False(t, ok, "a ttl at 65534 is not a status_list")

	_, ok = CWTStatusListClaim(map[int]any{65534: int64(43200)})
	assert.False(t, ok)
}

// TestCWTStatusListClaim_PrefersDraftLabel: when a token carries both, the
// registered label wins and the value at the legacy label is read as the
// ttl it now is.
func TestCWTStatusListClaim_PrefersDraftLabel(t *testing.T) {
	raw, ok := CWTStatusListClaim(map[int]any{
		65533: map[string]any{"bits": uint64(8), "lst": []byte{0xAA}},
		65534: uint64(43200),
	})
	require.True(t, ok)

	_, lst, err := CWTStatusListMembers(raw)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xAA}, lst)
}

// TestCWTStatusListMembers_BothKeySpellings: go-wallet-backend reads and
// writes the integer labels today, so vc reads them; the draft says text,
// so vc writes those. Both have to work on the read side or one side's
// change takes the other down.
func TestCWTStatusListMembers_BothKeySpellings(t *testing.T) {
	tests := []struct {
		name string
		raw  any
	}{
		{"draft text keys", map[string]any{"bits": uint64(4), "lst": []byte{0x0F}}},
		{"legacy integer labels", map[any]any{int64(1): uint64(4), int64(2): []byte{0x0F}}},
		{"text keys in an any-keyed map", map[any]any{"bits": uint64(4), "lst": []byte{0x0F}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bits, lst, err := CWTStatusListMembers(tt.raw)
			require.NoError(t, err)
			assert.Equal(t, 4, bits)
			assert.Equal(t, []byte{0x0F}, lst)
		})
	}
}

// TestAcceptedCWTTypHeader: the draft requires the full media type. The
// bare subtype is what vc wrote and is read, nothing else is.
func TestAcceptedCWTTypHeader(t *testing.T) {
	assert.True(t, AcceptedCWTTypHeader("application/statuslist+cwt"))
	assert.True(t, AcceptedCWTTypHeader("APPLICATION/STATUSLIST+CWT"))
	assert.True(t, AcceptedCWTTypHeader("statuslist+cwt"), "legacy bare subtype is read")
	assert.False(t, AcceptedCWTTypHeader("application/statuslist+jwt"))
	assert.False(t, AcceptedCWTTypHeader("application/cose"))
	assert.False(t, AcceptedCWTTypHeader(""))
}

// TestGenerateCWTWritesFullMediaTypeInProtectedHeader checks the bytes that
// actually go on the wire, not just the constant.
func TestGenerateCWTWritesFullMediaTypeInProtectedHeader(t *testing.T) {
	var coseSign1 cbor.Tag
	require.NoError(t, cbor.Unmarshal(generateTestCWT(t, 0), &coseSign1))

	components, ok := coseSign1.Content.([]any)
	require.True(t, ok)
	require.Len(t, components, 4)

	protectedBytes, ok := components[0].([]byte)
	require.True(t, ok)

	var headers map[int64]any
	require.NoError(t, cbor.Unmarshal(protectedBytes, &headers))
	assert.Equal(t, "application/statuslist+cwt", headers[16])
}
