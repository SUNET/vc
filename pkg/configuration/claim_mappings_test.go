package configuration

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyedPIDTemplate asks for the PID as an SD-JWT VC or as an mdoc, and
// maps each through the entries of its credential query.
const keyedPIDTemplate = `templates:
  - id: pid
    name: PID
    oidc_scopes: [pid]
    dcql:
      credentials:
        - id: pid_sd_jwt
          format: dc+sd-jwt
          meta: {vct_values: ["urn:eudi:pid:1"]}
          claims:
            - path: [given_name]
            - path: [family_name]
        - id: pid_mdoc
          format: mso_mdoc
          meta: {doctype_value: eu.europa.ec.eudi.pid.1}
          claims:
            - path: [eu.europa.ec.eudi.pid.1, given_name]
            - path: [eu.europa.ec.eudi.pid.1, family_name]
      credential_sets:
        - options: [[pid_sd_jwt], [pid_mdoc]]
    claim_mappings:
      pid_sd_jwt:
        - {path: [given_name], claim: given_name}
        - {path: [family_name], claim: family_name}
      %s:
        - {path: [eu.europa.ec.eudi.pid.1, given_name], claim: given_name}
        - {path: [eu.europa.ec.eudi.pid.1, family_name], claim: family_name}
`

// The verifier maps a vp_token answering either credential query of a
// keyed template through that query's entries, and refuses two
// presentations that give one OIDC claim different values.
func TestKeyedClaimMappingsMapEachQuery(t *testing.T) {
	config, err := loadTemplateText(t, keyedPIDTemplate, "pid_mdoc")
	require.NoError(t, err)
	require.Len(t, config.Templates, 1)
	mappings, err := config.Templates[0].GetClaimMappings()
	require.NoError(t, err)

	erika := map[string]any{"given_name": "Erika", "family_name": "Mustermann"}
	for name, tc := range map[string]struct {
		response map[string][]string
		want     map[string]any
	}{
		"an SD-JWT VC": {
			response: map[string][]string{"pid_sd_jwt": {sdJWTPresentation(t, erika)}},
			want:     erika,
		},
		"an mdoc": {
			response: map[string][]string{"pid_mdoc": {mdocPresentation(t, "eu.europa.ec.eudi.pid.1", erika)}},
			want:     erika,
		},
		"both with one value per claim": {
			response: map[string][]string{
				"pid_sd_jwt": {sdJWTPresentation(t, erika)},
				"pid_mdoc":   {mdocPresentation(t, "eu.europa.ec.eudi.pid.1", erika)},
			},
			want: erika,
		},
		"both with two values for given_name": {
			response: map[string][]string{
				"pid_sd_jwt": {sdJWTPresentation(t, erika)},
				"pid_mdoc":   {mdocPresentation(t, "eu.europa.ec.eudi.pid.1", map[string]any{"given_name": "Erica", "family_name": "Mustermann"})},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			vpToken, err := json.Marshal(tc.response)
			require.NoError(t, err)
			got, err := openid4vp.NewClaimsExtractor().ExtractAndMapClaims(t.Context(), string(vpToken), mappings)
			if tc.want == nil {
				require.ErrorContains(t, err, `two different values for the OIDC claim "given_name"`)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// A keyed claim_mappings whose key names no credential query of the
// template's dcql is refused when the templates load.
func TestKeyedClaimMappingsRefuseAnUnknownQuery(t *testing.T) {
	_, err := loadTemplateText(t, keyedPIDTemplate, "pid_mdl")
	require.ErrorContains(t, err, "pid_mdl names no credential query of the dcql")
}

// loadTemplateText loads the presentation request file template, with
// args filled in, as the verifier loads its directory of them.
func loadTemplateText(t *testing.T, template string, args ...any) (*PresentationRequestConfig, error) {
	t.Helper()
	dir := t.TempDir()
	text := []byte(fmt.Sprintf(template, args...))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "templates.yaml"), text, 0o600))
	return LoadPresentationRequests(t.Context(), dir)
}

// sdJWTPresentation returns an SD-JWT VC presentation that discloses
// claims in its payload.
func sdJWTPresentation(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return "eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig~"
}

// mdocPresentation returns a DeviceResponse (ISO/IEC 18013-5) that holds
// claims as the elements of namespace, each an IssuerSignedItem in a
// tag 24 bytestring.
func mdocPresentation(t *testing.T, namespace string, claims map[string]any) string {
	t.Helper()
	items := make([]cbor.Tag, 0, len(claims))
	for identifier, value := range claims {
		item, err := cbor.Marshal(map[string]any{"elementIdentifier": identifier, "elementValue": value})
		require.NoError(t, err)
		items = append(items, cbor.Tag{Number: 24, Content: item})
	}
	response, err := cbor.Marshal(map[string]any{
		"version": "1.0",
		"status":  0,
		"documents": []any{map[string]any{
			"docType":      namespace,
			"issuerSigned": map[string]any{"nameSpaces": map[string]any{namespace: items}},
		}},
	})
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(response)
}
