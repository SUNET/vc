package model

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr(s string) *string { return &s }

func TestDeclaredClaimNames_VCTM(t *testing.T) {
	m := &CredentialMetadata{VCTM: &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: []*string{ptr("given_name")}},
		{Path: []*string{ptr("family_name")}},
		// A nested claim contributes its top-level object, so an address
		// object from the provider is admitted and handled downstream.
		{Path: []*string{ptr("address"), ptr("street_address")}},
		{Path: []*string{ptr("address"), ptr("country")}},
		{Path: nil},            // malformed entries must not panic
		{Path: []*string{nil}}, //
	}}}

	names, loaded := m.DeclaredClaimNames()
	require.True(t, loaded)
	assert.Equal(t, map[string]bool{"given_name": true, "family_name": true, "address": true}, names)
}

func TestDeclaredClaimNames_MDDL(t *testing.T) {
	m := &CredentialMetadata{MDDL: &mdoc.MDDLSchema{Claims: map[string]mdoc.NamespaceClaims{
		"org.iso.18013.5.1": {"given_name": {}, "birth_date": {}},
	}}}

	names, loaded := m.DeclaredClaimNames()
	require.True(t, loaded)
	assert.Equal(t, map[string]bool{"given_name": true, "birth_date": true}, names,
		"MDDL document data is keyed by element ID, not namespaced")
}

// TestDeclaredClaimNames_NothingLoaded pins the distinction the second return
// value exists for: a credential type with no metadata loaded declares
// nothing, and that must not be mistaken for declaring an empty set.
func TestDeclaredClaimNames_NothingLoaded(t *testing.T) {
	names, loaded := (&CredentialMetadata{}).DeclaredClaimNames()
	assert.False(t, loaded)
	assert.Empty(t, names)

	// A loaded VCTM that happens to declare nothing is a different answer.
	names, loaded = (&CredentialMetadata{VCTM: &sdjwtvc.VCTM{}}).DeclaredClaimNames()
	assert.True(t, loaded)
	assert.Empty(t, names)
}
