package model

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// TestCheckClaimPathsRefusals has one fixture per refusal rule of the
// loader, each next to the configuration that differs only in what the rule
// refuses and loads.
func TestCheckClaimPathsRefusals(t *testing.T) {
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
			name:     "an attribute mapping names no array element",
			refused:  "external_api:\n  scopes:\n    ehic:\n      attribute_mapping:\n        degree: {claim: [degrees, 0, type]}\n",
			accepted: "external_api:\n  scopes:\n    ehic:\n      attribute_mapping:\n        degree: {claim: [degrees, type]}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, claimPathsCfg(t, tt.refused).CheckClaimPaths())
			assert.NoError(t, claimPathsCfg(t, tt.accepted).CheckClaimPaths())
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
