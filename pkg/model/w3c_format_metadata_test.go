package model

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/require"
)

// The metadata generator's W3C branch and handlers_issuer.go's issuance
// dispatch are two lists of the same thing - which formats this issuer
// treats as W3C VCs - and they disagreed in both directions.
//
// Appendix A.1 makes credential_definition REQUIRED for a W3C format, so
// the two errors are symmetric: a format in the metadata list but not the
// dispatch is advertised and unissuable (#686), and one in the dispatch but
// not the metadata list is issued with metadata missing a required member.
func TestW3CFormatsGetACredentialDefinition(t *testing.T) {
	generate := func(t *testing.T, format string) (hasDefinition bool) {
		t.Helper()
		metadata, err := (&IssuerMetadata{}).Generate(
			context.Background(), "https://issuer.sunet.se",
			map[string]*CredentialMetadata{
				"degree": {
					Format: format,
					VCTM:   &sdjwtvc.VCTM{VCT: "urn:example:degree"},
					VCTURL: "https://issuer.sunet.se/type-metadata/degree",
				},
			})
		require.NoError(t, err)
		credConfig, ok := metadata.CredentialConfigurationsSupported["degree"]
		require.True(t, ok)
		return credConfig.CredentialDefinition != nil
	}

	// Both formats issueVC20 dispatches on. vc+ld+json is the one that was
	// missing: it fell to the default branch and went out with no
	// credential_definition at all.
	for _, format := range []string{"ldp_vc", "vc+ld+json"} {
		t.Run(format+" carries a credential_definition", func(t *testing.T) {
			require.True(t, generate(t, format),
				"Appendix A.1 makes credential_definition REQUIRED for a W3C format")
		})
	}

	// The control: a non-W3C format must NOT grow one, or this test would
	// pass against a generator that attached it to everything.
	t.Run("dc+sd-jwt carries none", func(t *testing.T) {
		require.False(t, generate(t, "dc+sd-jwt"),
			"credential_definition is format-specific to W3C VCs")
	})
}
