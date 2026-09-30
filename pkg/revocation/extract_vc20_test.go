package revocation

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/vc20/contextstore"

	"github.com/stretchr/testify/require"
)

func vc20Status(entry any) map[string]any {
	return map[string]any{
		"type":             []any{"VerifiableCredential"},
		"credentialStatus": entry,
	}
}

func tokenStatusEntry() map[string]any {
	return map[string]any{
		"id":              "https://status.example.com/statuslists/7#42",
		"type":            contextstore.TokenStatusListEntryType,
		"statusListUri":   "https://status.example.com/statuslists/7",
		"statusListIndex": "42",
		"statusPurpose":   "revocation",
	}
}

// TestExtractCredentialStatus_VC20 is the counterpart to mdoc surfacing its
// MSO status under "status": VC 2.0 has no such claim, so the same single
// revocation check has to be able to read credentialStatus too.
func TestExtractCredentialStatus_VC20(t *testing.T) {
	ref := ExtractCredentialStatusReference(vc20Status(tokenStatusEntry()))
	require.NotNil(t, ref)
	require.Equal(t, SchemeStatusList, ref.Scheme)
	require.Equal(t, "https://status.example.com/statuslists/7", ref.URI)
	require.Equal(t, int64(42), ref.Index)
}

func TestExtractCredentialStatus_AcceptsASetAndATypeArray(t *testing.T) {
	entry := tokenStatusEntry()
	entry["type"] = []any{"SomethingElse", contextstore.TokenStatusListEntryType}

	ref := ExtractCredentialStatusReference(vc20Status([]any{
		map[string]any{"type": "BitstringStatusListEntry", "statusListCredential": "https://elsewhere.example.com/l"},
		entry,
	}))
	require.NotNil(t, ref, "a credential may carry several mechanisms; ours must still be found")
	require.Equal(t, int64(42), ref.Index)
}

func TestExtractCredentialStatus_IndexMustBeANonNegativeInteger(t *testing.T) {
	for name, bad := range map[string]any{
		"negative":    "-1",
		"fractional":  1.5,
		"nonNumeric":  "forty-two",
		"absent":      nil,
		"wrongType":   []any{1},
		"negativeNum": float64(-3),
	} {
		t.Run(name, func(t *testing.T) {
			entry := tokenStatusEntry()
			entry["statusListIndex"] = bad
			require.Nil(t, ExtractCredentialStatusReference(vc20Status(entry)))
		})
	}
}

func TestExtractCredentialStatus_NoStatusIsNotAReference(t *testing.T) {
	require.Nil(t, ExtractCredentialStatusReference(map[string]any{"type": []any{"VerifiableCredential"}}))
}

// TestValidate_UnreadableStatusIsRefused is the fail-closed rule: a
// credential that SAYS it carries revocation information, but whose entry no
// checker can read, must not come back as "not revocable". Otherwise a
// revoked credential passes on nothing more than an unrecognised type name.
func TestValidate_UnreadableStatusIsRefused(t *testing.T) {
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithKeyResolver(testKeyResolver{}),
	)
	require.NoError(t, err)
	registry := NewRegistry(checker)

	cases := map[string]map[string]any{
		"unknown credentialStatus type": vc20Status(map[string]any{
			"type": "SomeFutureMechanism", "foo": "bar",
		}),
		"malformed credentialStatus entry": vc20Status(map[string]any{
			"type": contextstore.TokenStatusListEntryType, "statusListUri": "",
		}),
		"malformed status claim": {
			"status": map[string]any{"status_list": map[string]any{"uri": "", "idx": 1}},
		},
		"status claim naming another mechanism": {
			"status": map[string]any{"some_other_list": map[string]any{"uri": "https://x.example", "idx": 1}},
		},
	}

	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := registry.Validate(t.Context(), claims)
			require.Error(t, err, "an unreadable status must not come back as not-revocable")
			require.Nil(t, result)
			require.Contains(t, err.Error(), "no registered checker could read")
		})
	}
}

// TestValidate_NoStatusIsStillNotRevocable: the guard above must not turn
// an ordinary credential without revocation information into an error.
func TestValidate_NoStatusIsStillNotRevocable(t *testing.T) {
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithKeyResolver(testKeyResolver{}),
	)
	require.NoError(t, err)
	registry := NewRegistry(checker)

	result, err := registry.Validate(t.Context(), map[string]any{"iss": "https://issuer.example.com"})
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestDeclaresStatus_NullCountsAsDeclared: `"credentialStatus": null` names
// a revocation mechanism and fails to describe it. That is a credential
// whose revocation state is unknown, not one that is not revocable, and a
// null used to slip past the guard because the check required a non-nil
// value.
func TestDeclaresStatus_NullCountsAsDeclared(t *testing.T) {
	for _, key := range []string{"status", "credentialStatus"} {
		t.Run(key+" null", func(t *testing.T) {
			require.True(t, declaresStatus(map[string]any{key: nil}))
		})
		t.Run(key+" present", func(t *testing.T) {
			require.True(t, declaresStatus(map[string]any{key: map[string]any{"type": "X"}}))
		})
	}

	require.False(t, declaresStatus(map[string]any{}))
	require.False(t, declaresStatus(map[string]any{"vct": "urn:x"}))
}

// TestRegistryValidate_NullStatusIsNotSilentlyNonRevocable proves the guard
// is reached through the production path, not just the predicate: a
// credential with a null credentialStatus must come back as "cannot
// determine", which fail_open then governs.
func TestRegistryValidate_NullStatusIsNotSilentlyNonRevocable(t *testing.T) {
	registry := NewRegistry()

	result, err := registry.Validate(t.Context(), map[string]any{"credentialStatus": nil})
	require.Error(t, err, "a declared-but-unreadable status must not read as non-revocable")
	require.Nil(t, result)
	require.Contains(t, err.Error(), "no registered checker could read")
}

// TestDeclaresStatus_ApplicationStatusClaimIsNotADeclaration: `status` is
// not exclusive to revocation. `"status": "active"` is an ordinary
// credential claim, and an mdoc data element may be named the same;
// treating either as a revocation declaration makes every such credential
// unverifiable rather than merely non-revocable.
//
// The draft's claim is an OBJECT - it holds status_list - so the shape is
// what separates them.
func TestDeclaresStatus_ApplicationStatusClaimIsNotADeclaration(t *testing.T) {
	require.False(t, declaresStatus(map[string]any{"status": "active"}),
		"a string status is somebody else's claim")
	require.False(t, declaresStatus(map[string]any{"status": 1}))
	require.False(t, declaresStatus(map[string]any{"status": []any{"a"}}))

	require.True(t, declaresStatus(map[string]any{
		"status": map[string]any{"status_list": map[string]any{"uri": "https://x", "idx": 1}},
	}), "the draft's claim is an object")
	require.True(t, declaresStatus(map[string]any{"status": map[string]any{"unknown_mechanism": 1}}),
		"an object naming a mechanism we cannot read is declared-but-unreadable")

	// credentialStatus is a VCDM term and means only this, so presence is
	// enough whatever the value.
	require.True(t, declaresStatus(map[string]any{"credentialStatus": "anything"}))
}

// TestRegistryValidate_ApplicationStatusClaimStillValidates proves the
// narrowing reaches the production path: an ordinary credential carrying a
// string `status` must come back non-revocable, not as an error that
// fail_open=false would turn into a rejection.
func TestRegistryValidate_ApplicationStatusClaimStillValidates(t *testing.T) {
	registry := NewRegistry()

	result, err := registry.Validate(t.Context(), map[string]any{"status": "active"})
	require.NoError(t, err)
	require.Nil(t, result)
}
