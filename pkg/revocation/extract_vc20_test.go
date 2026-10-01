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
			result, err := registry.ValidateShaped(t.Context(), claims, StatusClaimMayBeData)
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

	result, err := registry.ValidateShaped(t.Context(), map[string]any{"iss": "https://issuer.example.com"}, StatusClaimMayBeData)
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
			require.True(t, declaresStatus(map[string]any{key: nil}, StatusClaimMayBeData))
		})
		t.Run(key+" present", func(t *testing.T) {
			require.True(t, declaresStatus(map[string]any{key: map[string]any{"type": "X"}}, StatusClaimMayBeData))
		})
	}

	require.False(t, declaresStatus(map[string]any{}, StatusClaimMayBeData))
	require.False(t, declaresStatus(map[string]any{"vct": "urn:x"}, StatusClaimMayBeData))
}

// TestRegistryValidate_NullStatusIsNotSilentlyNonRevocable proves the guard
// is reached through the production path, not just the predicate: a
// credential with a null credentialStatus must come back as "cannot
// determine", which fail_open then governs.
func TestRegistryValidate_NullStatusIsNotSilentlyNonRevocable(t *testing.T) {
	registry := NewRegistry()

	result, err := registry.ValidateShaped(t.Context(), map[string]any{"credentialStatus": nil}, StatusClaimMayBeData)
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
	require.False(t, declaresStatus(map[string]any{"status": "active"}, StatusClaimMayBeData),
		"a string status is somebody else's claim")
	require.False(t, declaresStatus(map[string]any{"status": 1}, StatusClaimMayBeData))
	require.False(t, declaresStatus(map[string]any{"status": []any{"a"}}, StatusClaimMayBeData))

	require.True(t, declaresStatus(map[string]any{
		"status": map[string]any{"status_list": map[string]any{"uri": "https://x", "idx": 1}},
	}, StatusClaimMayBeData), "the draft's claim is an object")
	require.True(t, declaresStatus(map[string]any{"status": map[string]any{"unknown_mechanism": 1}}, StatusClaimMayBeData),
		"an object naming a mechanism we cannot read is declared-but-unreadable")

	// credentialStatus is a VCDM term and means only this, so presence is
	// enough whatever the value.
	require.True(t, declaresStatus(map[string]any{"credentialStatus": "anything"}, StatusClaimMayBeData))
}

// TestRegistryValidate_ApplicationStatusClaimStillValidates proves the
// narrowing reaches the production path: an ordinary credential carrying a
// string `status` must come back non-revocable, not as an error that
// fail_open=false would turn into a rejection.
func TestRegistryValidate_ApplicationStatusClaimStillValidates(t *testing.T) {
	registry := NewRegistry()

	result, err := registry.ValidateShaped(t.Context(), map[string]any{"status": "active"}, StatusClaimMayBeData)
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestStatusListIndex_RejectsUnsafeIntegers: a JSON number decodes to
// float64, which stops naming an integer exactly above 2^53. Converting a
// larger one yields a ROUNDED index, so the credential would be checked
// against a different entry than the one it names - and could land on a
// neighbour's VALID bit.
func TestStatusListIndex_RejectsUnsafeIntegers(t *testing.T) {
	const safe = float64(1<<53 - 1)

	got, ok := statusListIndex(safe)
	require.True(t, ok, "the largest exactly representable integer is still readable")
	require.Equal(t, int64(1<<53-1), got)

	for name, value := range map[string]float64{
		"just past the safe range": float64(1 << 53),
		"far past it":              1e30,
		"fractional":               3.5,
		"negative":                 -1,
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := statusListIndex(value)
			require.False(t, ok, "an index that cannot be read back as written must be refused, not rounded")
		})
	}

	// The exact forms are unaffected: a string or json.Number carries the
	// value without passing through float64 at all.
	got, ok = statusListIndex("9007199254740993")
	require.True(t, ok)
	require.Equal(t, int64(9007199254740993), got)
}

// TestDeclaresStatus_ReservedFormatsRefuseAMalformedStatus: SD-JWT VC and
// JWP reserve the `status` claim for the Token Status List reference, so a
// scalar there is a MALFORMED reference rather than an application claim.
// Reading it as the latter is how a credential whose revocation state is
// unknown gets accepted as non-revocable.
//
// mdoc is the exception, and the reason the shape has to be told: its
// claims include data elements, one of which may legitimately be named
// "status".
func TestDeclaresStatus_ReservedFormatsRefuseAMalformedStatus(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"a scalar":  {"status": "active"},
		"a number":  {"status": 1},
		"an array":  {"status": []any{"a"}},
		"a null":    {"status": nil},
		"an object": {"status": map[string]any{"status_list": map[string]any{}}},
	} {
		t.Run(name, func(t *testing.T) {
			require.True(t, declaresStatus(claims, StatusClaimIsReserved),
				"the format reserves the name, so anything under it was meant to be a reference")
		})
	}

	// And the mdoc reading is unchanged, or every credential with a data
	// element named status becomes unverifiable.
	require.False(t, declaresStatus(map[string]any{"status": "active"}, StatusClaimMayBeData))
}

// TestRegistryValidate_ReservedScalarStatusIsNotSilentlyNonRevocable proves
// it through Registry.Validate, which is where the consequence lands.
func TestRegistryValidate_ReservedScalarStatusIsNotSilentlyNonRevocable(t *testing.T) {
	registry := NewRegistry()

	result, err := registry.ValidateShaped(t.Context(), map[string]any{"status": "active"}, StatusClaimIsReserved)
	require.Error(t, err, "a malformed reference must read as unknown, not as non-revocable")
	require.Nil(t, result)

	result, err = registry.ValidateShaped(t.Context(), map[string]any{"status": "active"}, StatusClaimMayBeData)
	require.NoError(t, err, "an mdoc data element named status is not a reference")
	require.Nil(t, result)
}

// TestValidate_KeepsTheTwoArgumentShape: Validate is the signature this
// package exported before the shape parameter existed, and it still
// compiles and still means something specific - the strict reading, where
// `status` is reserved for the revocation reference.
//
// That is the right default for a caller who never said: of the two
// readings it is the one that refuses an unreadable `status` instead of
// passing it off as somebody's data element. mdoc callers, who are the
// exception, say so with ValidateShaped.
func TestValidate_KeepsTheTwoArgumentShape(t *testing.T) {
	registry := NewRegistry()

	// An mdoc data element named `status` holding a string. Under the
	// reserved reading this is a malformed status reference and must be
	// refused; under StatusClaimMayBeData it is ordinary claim data.
	claims := map[string]any{"status": "active"}

	result, err := registry.Validate(t.Context(), claims)
	require.Error(t, err, "the two-argument form must apply the strict reading, not the permissive one")
	require.Nil(t, result)
	require.Contains(t, err.Error(), "no registered checker could read")

	shaped, shapedErr := registry.ValidateShaped(t.Context(), claims, StatusClaimMayBeData)
	require.NoError(t, shapedErr, "and the permissive reading must still be reachable, for mdoc")
	require.Nil(t, shaped)
}
