package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompactTerm(t *testing.T) {
	for iri, want := range map[string]string{
		"https://www.w3.org/2018/credentials#VerifiableCredential":                "VerifiableCredential",
		"https://schemas.accredify.io/idvc/vocab/v1/vocab#IndividualIDCredential": "IndividualIDCredential",
		"https://example.org/types/Diploma":                                       "Diploma",
		"https://example.org/types/Diploma/":                                      "Diploma",
		"VerifiableCredential":                                                    "VerifiableCredential",
		"https://example.org/vocab#":                                              "https://example.org/vocab#",
		"https://example.org":                                                     "https://example.org",
		"":                                                                        "",
	} {
		assert.Equal(t, want, compactTerm(iri), iri)
	}
}

func TestWithCompactW3CTypeValues(t *testing.T) {
	const vc = "https://www.w3.org/2018/credentials#VerifiableCredential"
	const id = "https://schemas.accredify.io/idvc/vocab/v1/vocab#IndividualIDCredential"
	original := &DCQL{Credentials: []CredentialQuery{
		{ID: "w3c", Format: FormatLdpVCDCQL, Meta: MetaQuery{TypeValues: [][]string{{vc, id}}}},
		{ID: "sdjwt", Format: FormatSDJWTVC, Meta: MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}

	compact := original.WithCompactW3CTypeValues()

	require.NotNil(t, compact)
	assert.Equal(t, [][]string{{"VerifiableCredential", "IndividualIDCredential"}}, compact.Credentials[0].Meta.TypeValues)
	assert.Equal(t, []string{"urn:eudi:pid:1"}, compact.Credentials[1].Meta.VCTValues, "other formats are left alone")
	assert.Equal(t, [][]string{{vc, id}}, original.Credentials[0].Meta.TypeValues,
		"the receiver keeps the expanded form: the response check matches on it")
}

func TestWithCompactW3CTypeValuesNil(t *testing.T) {
	var q *DCQL
	assert.Nil(t, q.WithCompactW3CTypeValues())
}
