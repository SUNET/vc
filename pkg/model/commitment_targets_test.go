package model

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

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
		targets, err := mdocMeta(map[string]*CommitmentClaim{path: sscClaim()}).ResolveCommitmentTargets(CredentialSchemas{MDoc: nymSchema()})
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
	}).ResolveCommitmentTargets(CredentialSchemas{MDoc: nymSchema()})
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
		targets, err := meta.ResolveCommitmentTargets(CredentialSchemas{MDoc: schema})
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
	_, err := meta.ResolveCommitmentTargets(CredentialSchemas{MDoc: schema})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one element")
}

// A nil claim must be reported, not dereferenced. This runs before the
// struct validation that would otherwise reject it, so a panic here takes
// the service down at startup with a stack trace instead of a message.
func TestANilClaimIsReportedNotDereferenced(t *testing.T) {
	assert.NotPanics(t, func() {
		_, err := mdocMeta(map[string]*CommitmentClaim{"ssc": nil}).ResolveCommitmentTargets(CredentialSchemas{MDoc: nymSchema()})
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
	_, err := mdocMeta(map[string]*CommitmentClaim{"ssc": claim}).ResolveCommitmentTargets(CredentialSchemas{MDoc: nymSchema()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bstr")
}

func TestEncodingDefaultsByFormat(t *testing.T) {
	targets, err := mdocMeta(map[string]*CommitmentClaim{"ssc": sscClaim()}).ResolveCommitmentTargets(CredentialSchemas{MDoc: nymSchema()})
	require.NoError(t, err)
	assert.Equal(t, CommitmentEncodingBase64, targets[0].Encoding, "mso_mdoc carries a bstr as base64")

	sdjwt := &CredentialMetadata{
		Format:      openid4vp.FormatSDJWTVC,
		Commitments: map[string]*CommitmentClaim{"ssc": sscClaim()},
	}
	targets, err = sdjwt.ResolveCommitmentTargets(CredentialSchemas{})
	require.NoError(t, err)
	assert.Equal(t, CommitmentEncodingHex, targets[0].Encoding, "everything else carries the claim itself")
	assert.Equal(t, "ssc", targets[0].Element, "and has no schema to normalise against")
}

func TestUndeclaredTargetIsRefused(t *testing.T) {
	_, err := mdocMeta(map[string]*CommitmentClaim{"psc": sscClaim()}).ResolveCommitmentTargets(CredentialSchemas{MDoc: nymSchema()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "declares no such element")
}

func TestNoCommitmentsResolvesToNothing(t *testing.T) {
	targets, err := (&CredentialMetadata{Format: openid4vp.FormatMsoMdoc}).ResolveCommitmentTargets(CredentialSchemas{MDoc: nymSchema()})
	require.NoError(t, err)
	assert.Empty(t, targets)

	targets, err = (*CredentialMetadata)(nil).ResolveCommitmentTargets(CredentialSchemas{})
	require.NoError(t, err)
	assert.Empty(t, targets)
}

// In a nested document "a" and "a.b" are mutually exclusive: the outer is
// written as a string, so writing the inner has to descend through it and
// cannot. Startup accepted that configuration and every issuance then
// failed with a path conflict - deterministically, which is exactly the
// kind of error an operator should be told about at startup.
func TestNestedParentAndChildTargetsAreRefused(t *testing.T) {
	for _, pair := range [][2]string{
		{"a", "a.b"},
		{"a.b", "a"},
		{"identity", "identity.ssc"},
		{"a.b", "a.b.c"},
	} {
		meta := &CredentialMetadata{
			Format: openid4vp.FormatSDJWTVC,
			Commitments: map[string]*CommitmentClaim{
				pair[0]: sscClaim(),
				pair[1]: sscClaim(),
			},
		}
		_, err := meta.ResolveCommitmentTargets(CredentialSchemas{})
		require.Error(t, err, "%q and %q cannot both be written", pair[0], pair[1])
		assert.Contains(t, err.Error(), "nested under the other")
	}

	// Siblings and merely-similar names are fine.
	for _, pair := range [][2]string{{"a", "b"}, {"a", "ab"}, {"a.b", "a.c"}} {
		meta := &CredentialMetadata{
			Format: openid4vp.FormatSDJWTVC,
			Commitments: map[string]*CommitmentClaim{
				pair[0]: sscClaim(),
				pair[1]: sscClaim(),
			},
		}
		_, err := meta.ResolveCommitmentTargets(CredentialSchemas{})
		assert.NoError(t, err, "%q and %q are independent", pair[0], pair[1])
	}

	// A flat document has no nesting: a dotted element identifier is one
	// key and nothing descends into it.
	flat := &CredentialMetadata{
		Format: openid4vp.FormatMsoMdoc,
		Commitments: map[string]*CommitmentClaim{
			"a":   sscClaim(),
			"a.b": sscClaim(),
		},
	}
	_, err := flat.ResolveCommitmentTargets(CredentialSchemas{})
	assert.NoError(t, err, "mdoc element identifiers are flat keys, not paths")
}

// A commitment is injected as a JSON string, so only elements that can
// carry one may be targets. int and uint fail conversion AFTER a status
// list entry has been allocated; bool, array and map do not fail at all -
// convertElementValue passes an unrecognised value_type through, so the
// commitment is signed as a CBOR text string where the schema promises
// something else, and only a verifier finds out.
func TestOnlyStringCarryingElementsMayHoldACommitment(t *testing.T) {
	for valueType, allowed := range map[string]bool{
		"bstr":      true,
		"tstr":      true,
		"int":       false,
		"uint":      false,
		"bool":      false,
		"array":     false,
		"map":       false,
		"full-date": false,
		"tdate":     false,
	} {
		schema := &mdoc.MDDLSchema{
			DocType: "org.example.1",
			Claims:  map[string]mdoc.NamespaceClaims{"org.example.1": {"ssc": {ValueType: valueType}}},
		}
		meta := &CredentialMetadata{
			Format:      openid4vp.FormatMsoMdoc,
			Commitments: map[string]*CommitmentClaim{"ssc": sscClaim()},
		}
		_, err := meta.ResolveCommitmentTargets(CredentialSchemas{MDoc: schema})
		if allowed {
			assert.NoError(t, err, "value_type %q can carry a commitment", valueType)
			continue
		}
		require.Error(t, err, "value_type %q cannot carry a commitment", valueType)
		assert.Contains(t, err.Error(), "cannot carry a commitment")
	}
}

// A format's signing layer writes some claims for itself, AFTER the
// document this feature injects into has been parsed. A commitment
// configured at one of them is injected perfectly well and then
// overwritten, so the credential carries the envelope value instead of
// commit(seed) - with no error, because both writes succeeded.
func TestTargetsTheSigningLayerOverwritesAreRefused(t *testing.T) {
	// The SD-JWT builder assigns every one of these unconditionally.
	for _, claim := range []string{"iat", "nbf", "exp", "iss", "jti", "vct", "vct#integrity", "cnf", "status"} {
		meta := &CredentialMetadata{
			Format:      openid4vp.FormatSDJWTVC,
			Commitments: map[string]*CommitmentClaim{claim: sscClaim()},
		}
		_, err := meta.ResolveCommitmentTargets(CredentialSchemas{})
		require.Error(t, err, "a commitment at %q would be replaced by the builder", claim)
		assert.Contains(t, err.Error(), "silently replaced")
	}

	// The ROOT segment is what matters: the builder assigns "status" as a
	// whole object, so a nested target under it is destroyed just as
	// completely.
	nested := &CredentialMetadata{
		Format:      openid4vp.FormatSDJWTVC,
		Commitments: map[string]*CommitmentClaim{"status.value": sscClaim()},
	}
	_, err := nested.ResolveCommitmentTargets(CredentialSchemas{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "silently replaced")

	// A name that merely starts the same way is not reserved, and the
	// SD-JWT envelope names mean nothing in another format.
	for _, tc := range []struct{ format, path string }{
		{openid4vp.FormatSDJWTVC, "issuing_authority"},
		{openid4vp.FormatSDJWTVC, "statuses"},
		{openid4vp.FormatSDJWTVC, "ssc"},
		{openid4vp.FormatMsoMdoc, "iss"},
	} {
		meta := &CredentialMetadata{
			Format:      tc.format,
			Commitments: map[string]*CommitmentClaim{tc.path: sscClaim()},
		}
		_, err := meta.ResolveCommitmentTargets(CredentialSchemas{})
		assert.NoError(t, err, "%s: %q is not written by the signing layer", tc.format, tc.path)
	}
}

// Commitments are implemented for the two formats whose signing layers
// this code has a complete account of. The W3C path in particular needs
// something it does not have: the proof covers the RDF canonical form,
// where a term the JSON-LD contexts do not define is dropped, while
// ToCompactJSON returns the original JSON - so the commitment would be
// visible in the credential and NOT covered by the proof over it, free to
// be altered without invalidating the signature.
//
// Refused rather than injected, because that outcome is worse than the
// format not being supported. It subsumes the reserved subject identifier
// these formats used to carry.
func TestOnlyFormatsWithAccountedSigningLayersAreSupported(t *testing.T) {
	for _, format := range []string{openid4vp.FormatMsoMdoc, openid4vp.FormatSDJWTVC, "vc+sd-jwt", ""} {
		meta := &CredentialMetadata{
			Format:      format,
			Commitments: map[string]*CommitmentClaim{"ssc": sscClaim()},
		}
		schemas := CredentialSchemas{}
		if format == openid4vp.FormatMsoMdoc {
			schemas.MDoc = nymSchema()
		}
		_, err := meta.ResolveCommitmentTargets(schemas)
		assert.NoError(t, err, "%q is supported", format)
	}

	for _, format := range []string{openid4vp.FormatLdpVC, openid4vp.FormatVC20JSON} {
		meta := &CredentialMetadata{
			Format:      format,
			Commitments: map[string]*CommitmentClaim{"ssc": sscClaim()},
		}
		_, err := meta.ResolveCommitmentTargets(CredentialSchemas{})
		require.Error(t, err, "%q cannot carry a commitment the proof covers", format)
		assert.Contains(t, err.Error(), "not implemented")
		assert.Contains(t, err.Error(), "unprotected")
	}

	// And anything else, named rather than silently accepted.
	other := &CredentialMetadata{
		Format:      "jwt_vc_json",
		Commitments: map[string]*CommitmentClaim{"ssc": sscClaim()},
	}
	_, err := other.ResolveCommitmentTargets(CredentialSchemas{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

// An SD-JWT commitment must be a claim the type metadata makes
// selectively disclosable.
//
// MakeCredential turns a claim into a disclosure only when the VCTM lists
// its path with sd "always". Anything else is signed in the CLEAR, so a
// misspelled or undeclared commitment path is not missing - it is issued
// permanently in a form the holder cannot withhold. For a seed commitment
// that is the whole value at stake: a stable identifier for its holder,
// handed to every verifier unconditionally.
func TestSDJWTCommitmentsMustBeSelectivelyDisclosable(t *testing.T) {
	path := func(segments ...string) []*string {
		out := make([]*string, 0, len(segments))
		for _, s := range segments {
			out = append(out, &s)
		}
		return out
	}
	vctm := &sdjwtvc.VCTM{
		VCT: "urn:example:nym_auth:1",
		Claims: []sdjwtvc.Claim{
			{Path: path("ssc"), SD: "always"},
			{Path: path("birth_date"), SD: "always"},
			{Path: path("issuing_country"), SD: "allowed"},
			{Path: path("issuer_note")},
			{Path: path("nested", "inner"), SD: "always"},
		},
	}
	meta := func(target string) *CredentialMetadata {
		return &CredentialMetadata{
			Format:      openid4vp.FormatSDJWTVC,
			Commitments: map[string]*CommitmentClaim{target: sscClaim()},
		}
	}

	for _, target := range []string{"ssc", "nested.inner"} {
		_, err := meta(target).ResolveCommitmentTargets(CredentialSchemas{VCTM: vctm})
		assert.NoError(t, err, "%q is declared sd always", target)
	}

	for _, tc := range []struct{ target, want string }{
		{"issuing_country", `sd "allowed"`},
		{"issuer_note", `sd "allowed"`}, // absent sd defaults to allowed
		{"ssc_typo", "does not declare it"},
		{"nested", "does not declare it"}, // the parent is not itself a claim
	} {
		_, err := meta(tc.target).ResolveCommitmentTargets(CredentialSchemas{VCTM: vctm})
		require.Error(t, err, "%q is not selectively disclosable", tc.target)
		assert.Contains(t, err.Error(), tc.want)
		assert.Contains(t, err.Error(), "could not withhold it")
	}

	// No VCTM to check against means the caller has none; the issuer
	// checks again with the one it is sent.
	_, err := meta("anything").ResolveCommitmentTargets(CredentialSchemas{})
	assert.NoError(t, err)

	// And the rule is SD-JWT's: an mdoc element is selectively
	// disclosable by construction.
	mdocMeta := &CredentialMetadata{
		Format:      openid4vp.FormatMsoMdoc,
		Commitments: map[string]*CommitmentClaim{"ssc": sscClaim()},
	}
	_, err = mdocMeta.ResolveCommitmentTargets(CredentialSchemas{MDoc: nymSchema(), VCTM: vctm})
	assert.NoError(t, err)
}

// Every spelling that reaches the SD-JWT signing path gets the SD-JWT
// checks. Checking only the current identifier meant a legacy-spelled
// scope silently got neither the VCTM disclosure check nor the
// reserved-claim check - so its commitment could be signed in the clear,
// or at a path the builder overwrites, with nothing reporting either.
func TestEverySDJWTSpellingGetsTheSDJWTChecks(t *testing.T) {
	sd := func(p string) []*string { return []*string{&p} }
	vctm := &sdjwtvc.VCTM{
		VCT:    "urn:example:nym_auth:1",
		Claims: []sdjwtvc.Claim{{Path: sd("ssc"), SD: "always"}},
	}

	for _, format := range []string{openid4vp.FormatSDJWTVC, "vc+sd-jwt", ""} {
		undeclared := &CredentialMetadata{
			Format:      format,
			Commitments: map[string]*CommitmentClaim{"not_in_the_vctm": sscClaim()},
		}
		_, err := undeclared.ResolveCommitmentTargets(CredentialSchemas{VCTM: vctm})
		require.Error(t, err, "format %q must get the disclosure check", format)
		assert.Contains(t, err.Error(), "could not withhold it")

		reserved := &CredentialMetadata{
			Format:      format,
			Commitments: map[string]*CommitmentClaim{"cnf": sscClaim()},
		}
		_, err = reserved.ResolveCommitmentTargets(CredentialSchemas{VCTM: vctm})
		require.Error(t, err, "format %q must get the reserved-claim check", format)
		assert.Contains(t, err.Error(), "silently replaced")

		ok := &CredentialMetadata{
			Format:      format,
			Commitments: map[string]*CommitmentClaim{"ssc": sscClaim()},
		}
		_, err = ok.ResolveCommitmentTargets(CredentialSchemas{VCTM: vctm})
		assert.NoError(t, err, "format %q: a declared, non-reserved target is fine", format)
	}
}

// A VCTM path of ["a.b"] is a single top-level key that happens to contain
// a dot. A configured "a.b" is always injected NESTED, so the two are not
// the same claim - and treating them as equal would let the commitment be
// written somewhere MakeCredential never turns into a disclosure, leaving
// it in the clear. The comparison meant to catch that must not reintroduce
// it.
func TestVCTMPathSegmentsAreNotFlattened(t *testing.T) {
	literal := "a.b"
	outer, inner := "a", "b"

	declaresLiteralKey := &sdjwtvc.VCTM{
		VCT:    "urn:example:1",
		Claims: []sdjwtvc.Claim{{Path: []*string{&literal}, SD: "always"}},
	}
	declaresNested := &sdjwtvc.VCTM{
		VCT:    "urn:example:1",
		Claims: []sdjwtvc.Claim{{Path: []*string{&outer, &inner}, SD: "always"}},
	}
	meta := &CredentialMetadata{
		Format:      openid4vp.FormatSDJWTVC,
		Commitments: map[string]*CommitmentClaim{"a.b": sscClaim()},
	}

	_, err := meta.ResolveCommitmentTargets(CredentialSchemas{VCTM: declaresLiteralKey})
	require.Error(t, err, "a literal top-level key is not the nested path injection writes")
	assert.Contains(t, err.Error(), "does not declare it")

	_, err = meta.ResolveCommitmentTargets(CredentialSchemas{VCTM: declaresNested})
	assert.NoError(t, err, "the nested declaration is the one that matches")
}

// The disclosure machinery's own claims are reserved, and that beats a
// VCTM declaring them disclosable: _sd_alg and _sd are written by the
// builder regardless, so a commitment there is replaced whatever the type
// metadata says. The reserved check therefore has to run before the
// disclosability one, and this pins that ordering.
func TestDisclosureMachineryClaimsAreReservedEvenWhenDeclared(t *testing.T) {
	always := func(p string) sdjwtvc.Claim { return sdjwtvc.Claim{Path: []*string{&p}, SD: "always"} }
	vctm := &sdjwtvc.VCTM{
		VCT:    "urn:example:1",
		Claims: []sdjwtvc.Claim{always("_sd_alg"), always("_sd")},
	}

	for _, claim := range []string{"_sd_alg", "_sd"} {
		meta := &CredentialMetadata{
			Format:      openid4vp.FormatSDJWTVC,
			Commitments: map[string]*CommitmentClaim{claim: sscClaim()},
		}
		_, err := meta.ResolveCommitmentTargets(CredentialSchemas{VCTM: vctm})
		require.Error(t, err, "%s is written by the builder whatever the VCTM says", claim)
		assert.Contains(t, err.Error(), "silently replaced")
	}
}
