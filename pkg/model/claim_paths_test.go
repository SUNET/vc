package model

import (
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/mdoc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// TestResolveClaimPaths checks, for each role a claim plays, that the
// dotted form of a configuration and its pointer form read as the same
// claim, written down by hand.
func TestResolveClaimPaths(t *testing.T) {
	const nymAuth = "eu.europa.ec.eudi.nym_auth.1"
	presentation := func(from, claims string) string {
		return "presentation:\n  scopes:\n    nym_auth:\n      from:\n        " + from + ":\n" + claims
	}
	derivations := func(list string) string {
		return presentation("pid", "          derivations:\n"+list)
	}
	requiredClaim := func(c *Cfg) claimpath.Pointer {
		for _, accepted := range c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From {
			return accepted.RequiredClaims[0].Path
		}
		return claimpath.Pointer{}
	}
	derivation := func(i int) func(*Cfg) *primitives.Derivation {
		return func(c *Cfg) *primitives.Derivation {
			return &c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"].Derivations[i]
		}
	}

	tests := []struct {
		name            string
		dotted, pointer string
		claim           func(*Cfg) claimpath.Pointer
		want            claimpath.Pointer
	}{
		{
			name:    "a claim of a presented JSON-based credential",
			dotted:  presentation("pid", "          required_claims:\n            address.locality: []\n"),
			pointer: presentation("pid", "          required_claims:\n            - path: [address, locality]\n"),
			claim:   requiredClaim,
			want:    claimpath.Keys("address", "locality"),
		},
		{
			name:    "a qualified claim of a presented mdoc",
			dotted:  presentation("pid_mdoc", "          required_claims:\n            eu.europa.ec.eudi.pid.1.birth_date: []\n"),
			pointer: presentation("pid_mdoc", "          required_claims:\n            - path: [eu.europa.ec.eudi.pid.1, birth_date]\n"),
			claim:   requiredClaim,
			want:    claimpath.Keys("eu.europa.ec.eudi.pid.1", "birth_date"),
		},
		{
			name:    "a bare claim of a presented mdoc",
			dotted:  presentation("pid_mdoc", "          required_claims:\n            given_name: []\n"),
			pointer: presentation("pid_mdoc", "          required_claims:\n            - path: [org.iso.18013.5.1, given_name]\n"),
			claim:   requiredClaim,
			want:    claimpath.Keys("org.iso.18013.5.1", "given_name"),
		},
		{
			name:    "a claim of a JSON-based document",
			dotted:  "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      defaults:\n        address.country: SE\n",
			pointer: "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      defaults:\n        - {path: [address, country], value: SE}\n",
			claim:   func(c *Cfg) claimpath.Pointer { return c.APIGW.DataSources.Assertion.Scopes["ehic"].Defaults[0].Path },
			want:    claimpath.Keys("address", "country"),
		},
		{
			name:    "an element an mdoc document's MDDL declares",
			dotted:  derivations("            - copy: {input: birthdate, output: birth_date}\n"),
			pointer: derivations("            - copy: {input: [birthdate], output: [" + nymAuth + ", birth_date]}\n"),
			claim:   func(c *Cfg) claimpath.Pointer { return derivation(0)(c).Copy.Output },
			want:    claimpath.Keys(nymAuth, "birth_date"),
		},
		{
			name:    "a key an mdoc document's MDDL does not declare",
			dotted:  derivations("            - copy: {input: birthdate, output: a.b}\n"),
			pointer: derivations("            - copy: {input: [birthdate], output: [a.b]}\n"),
			claim:   func(c *Cfg) claimpath.Pointer { return derivation(0)(c).Copy.Output },
			want:    claimpath.Keys("a.b"),
		},
		{
			name:    "a derivation input an earlier derivation writes",
			dotted:  derivations("            - copy: {input: birthdate, output: a.b}\n            - copy: {input: a.b, output: birth_date}\n"),
			pointer: derivations("            - copy: {input: [birthdate], output: [a.b]}\n            - copy: {input: [a.b], output: [" + nymAuth + ", birth_date]}\n"),
			claim:   func(c *Cfg) claimpath.Pointer { return derivation(1)(c).Copy.Input },
			want:    claimpath.Keys("a.b"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for form, dataSources := range map[string]string{"dotted": tt.dotted, "pointer": tt.pointer} {
				cfg := claimPathsCfg(t, dataSources)
				require.NoError(t, cfg.ResolveClaimPaths(), form)
				assert.Equal(t, tt.want, tt.claim(cfg), form)
			}
		})
	}
}

// TestResolveClaimPathsRefusals has one fixture per refusal rule of the
// loader, each next to the configuration that differs only in what the rule
// refuses and loads.
func TestResolveClaimPathsRefusals(t *testing.T) {
	datastore := func(authScope string) string {
		return "datastore:\n  scopes:\n    ehic:\n      auth_provider: openid4vp\n      auth_scopes:\n        pid:\n" + authScope
	}
	tests := []struct {
		name              string
		refused, accepted string
	}{
		{
			name:     "a copy targets a top-level claim of the issued document",
			refused:  datastore("          auth_claims: [[given_name]]\n          document_claims:\n            - {from: [birthdate], to: [a, b]}\n"),
			accepted: datastore("          auth_claims: [[given_name]]\n          document_claims:\n            - {from: [birthdate], to: [a]}\n"),
		},
		{
			name:     "a derivation input names one claim",
			refused:  "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      derivations:\n        - copy: {input: [nationalities, null], output: [nationality]}\n",
			accepted: "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      derivations:\n        - copy: {input: [nationalities, 0], output: [nationality]}\n",
		},
		{
			name:     "an auth claim names an identity attribute",
			refused:  datastore("          auth_claims: [[nationalities, 0]]\n"),
			accepted: datastore("          auth_claims: [[nationalities, 0]]\n          identity_attributes: [{path: [nationalities, 0], attribute: given_name}]\n"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, claimPathsCfg(t, tt.refused).ResolveClaimPaths())
			assert.NoError(t, claimPathsCfg(t, tt.accepted).ResolveClaimPaths())
		})
	}
}

// claimPathsCfg is a configuration with the credentials the table's claims
// belong to, and the data sources of the case.
func claimPathsCfg(t *testing.T, dataSources string) *Cfg {
	t.Helper()
	var sources DataSources
	require.NoError(t, yaml.Unmarshal([]byte(dataSources), &sources))
	declares := func(namespace string, elements ...string) *mdoc.MDDLSchema {
		claims := mdoc.NamespaceClaims{}
		for _, element := range elements {
			claims[element] = mdoc.ClaimMetadata{}
		}
		return &mdoc.MDDLSchema{Claims: map[string]mdoc.NamespaceClaims{namespace: claims}}
	}
	return &Cfg{
		Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{
			"pid":      {Format: "dc+sd-jwt"},
			"ehic":     {Format: "dc+sd-jwt"},
			"pid_mdoc": {Format: "mso_mdoc", MDDL: declares("eu.europa.ec.eudi.pid.1", "birth_date", "given_name")},
			"nym_auth": {Format: "mso_mdoc", MDDL: declares("eu.europa.ec.eudi.nym_auth.1", "birth_date")},
		}},
		APIGW: &APIGW{DataSources: sources},
	}
}
