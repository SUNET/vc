package model

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nymSchema() *mdoc.MDDLSchema {
	return &mdoc.MDDLSchema{
		DocType: "eu.europa.ec.eudi.nym_auth.1",
		Claims: map[string]mdoc.NamespaceClaims{
			"eu.europa.ec.eudi.nym_auth.1": {
				"birth_date": {Mandatory: true, ValueType: "full-date"},
				"ssc":        {Mandatory: true, ValueType: "bstr"},
			},
		},
	}
}

func mdocMeta(commitments map[string]*CommitmentClaim) *CredentialMetadata {
	return &CredentialMetadata{
		Format:      openid4vp.FormatMsoMdoc,
		MDDL:        nymSchema(),
		Commitments: commitments,
	}
}

func sscClaim() *CommitmentClaim { return &CommitmentClaim{Seed: "primary", Subject: "pan"} }

// An mdoc document is flat and keyed by BARE element identifier. The
// namespace-qualified spelling is how the claim is named everywhere else
// in the configuration, so it is accepted - and normalised, because
// writing it verbatim puts the value where the signer never looks.
func TestQualifiedPathResolvesToTheBareElement(t *testing.T) {
	for _, path := range []string{"ssc", "eu.europa.ec.eudi.nym_auth.1.ssc"} {
		targets, err := mdocMeta(map[string]*CommitmentClaim{path: sscClaim()}).ResolveCommitmentTargets(nymSchema())
		require.NoError(t, err)
		require.Len(t, targets, 1)
		assert.Equal(t, "ssc", targets[0].Element, "%q must resolve to the key the signer reads", path)
		assert.Equal(t, path, targets[0].Path, "and keep the configured spelling for error messages")
	}
}

// Two configured paths may legitimately spell the same element. Neither
// has been written when the existing-value check runs, so both pass it and
// the second write silently replaces the first commitment.
func TestTwoPathsResolvingToOneElementAreRefused(t *testing.T) {
	_, err := mdocMeta(map[string]*CommitmentClaim{
		"ssc":                              sscClaim(),
		"eu.europa.ec.eudi.nym_auth.1.ssc": sscClaim(),
	}).ResolveCommitmentTargets(nymSchema())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "silently overwrite")
	assert.Contains(t, err.Error(), "ssc")
}

// A dotted path can be a literal element identifier in one namespace AND
// a namespace-qualified spelling in another. Resolving both in one pass
// over a map picks whichever namespace came up first, so startup and
// issuance could settle on different elements - and different carriers.
func TestAmbiguousPathsResolveTheSameWayEveryTime(t *testing.T) {
	schema := &mdoc.MDDLSchema{
		DocType: "org.example.1",
		Claims: map[string]mdoc.NamespaceClaims{
			// A literal element identifier that happens to contain dots.
			"org.example.a": {"org.example.b.ssc": {ValueType: "tstr"}},
			// And a namespace for which the same string is a qualified
			// spelling of a DIFFERENT element.
			"org.example.b": {"ssc": {ValueType: "bstr"}},
		},
	}
	meta := &CredentialMetadata{
		Format:      openid4vp.FormatMsoMdoc,
		MDDL:        schema,
		Commitments: map[string]*CommitmentClaim{"org.example.b.ssc": sscClaim()},
	}

	// The exact match wins, in a full pass before any qualified matching,
	// and it wins on every one of these runs rather than most of them.
	for range 50 {
		targets, err := meta.ResolveCommitmentTargets(schema)
		require.NoError(t, err)
		require.Len(t, targets, 1)
		assert.Equal(t, "org.example.b.ssc", targets[0].Element,
			"an exact element identifier must beat a qualified spelling, deterministically")
	}
}

// Qualified in two namespaces at once is genuinely ambiguous, and is
// refused rather than resolved by whichever came first.
func TestAQualifiedPathMatchingTwoNamespacesIsRefused(t *testing.T) {
	schema := &mdoc.MDDLSchema{
		DocType: "org.example.1",
		Claims: map[string]mdoc.NamespaceClaims{
			"org.a":   {"b.ssc": {ValueType: "bstr"}},
			"org.a.b": {"ssc": {ValueType: "bstr"}},
		},
	}
	meta := &CredentialMetadata{
		Format:      openid4vp.FormatMsoMdoc,
		MDDL:        schema,
		Commitments: map[string]*CommitmentClaim{"org.a.b.ssc": sscClaim()},
	}
	_, err := meta.ResolveCommitmentTargets(schema)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one element")
}

// A nil claim must be reported, not dereferenced. This runs before the
// struct validation that would otherwise reject it, so a panic here takes
// the service down at startup with a stack trace instead of a message.
func TestANilClaimIsReportedNotDereferenced(t *testing.T) {
	assert.NotPanics(t, func() {
		_, err := mdocMeta(map[string]*CommitmentClaim{"ssc": nil}).ResolveCommitmentTargets(nymSchema())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})
}

// A bstr element is decoded as standard base64, and a 64-character hex
// commitment is itself valid base64 - so hex does not fail, it decodes to
// 48 bytes of nothing and is signed as the commitment.
func TestHexAgainstABstrTargetIsRefused(t *testing.T) {
	claim := sscClaim()
	claim.Encoding = CommitmentEncodingHex
	_, err := mdocMeta(map[string]*CommitmentClaim{"ssc": claim}).ResolveCommitmentTargets(nymSchema())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bstr")
}

func TestEncodingDefaultsByFormat(t *testing.T) {
	targets, err := mdocMeta(map[string]*CommitmentClaim{"ssc": sscClaim()}).ResolveCommitmentTargets(nymSchema())
	require.NoError(t, err)
	assert.Equal(t, CommitmentEncodingBase64, targets[0].Encoding, "mso_mdoc carries a bstr as base64")

	sdjwt := &CredentialMetadata{
		Format:      openid4vp.FormatSDJWTVC,
		Commitments: map[string]*CommitmentClaim{"ssc": sscClaim()},
	}
	targets, err = sdjwt.ResolveCommitmentTargets(nil)
	require.NoError(t, err)
	assert.Equal(t, CommitmentEncodingHex, targets[0].Encoding, "everything else carries the claim itself")
	assert.Equal(t, "ssc", targets[0].Element, "and has no schema to normalise against")
}

func TestUndeclaredTargetIsRefused(t *testing.T) {
	_, err := mdocMeta(map[string]*CommitmentClaim{"psc": sscClaim()}).ResolveCommitmentTargets(nymSchema())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "declares no such element")
}

func TestNoCommitmentsResolvesToNothing(t *testing.T) {
	targets, err := (&CredentialMetadata{Format: openid4vp.FormatMsoMdoc}).ResolveCommitmentTargets(nymSchema())
	require.NoError(t, err)
	assert.Empty(t, targets)

	targets, err = (*CredentialMetadata)(nil).ResolveCommitmentTargets(nil)
	require.NoError(t, err)
	assert.Empty(t, targets)
}
