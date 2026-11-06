package configuration

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A derivation list in the earlier release's spellings loads and runs over
// an assertion's claims as the earlier release ran it. The expected
// document, cached opening claims and opening are the earlier release's
// (main at ff1df957) output on the same configuration and claims. A
// replica of either release opens the opening claims the other caches.
func TestEarlierReleaseDerivationsRunAsTheEarlierReleaseRanThem(t *testing.T) {
	const opening = "- hash_commitment:\n    path: [eu.europa.ec.eudi.nym_auth.1, ssc]\n    opening: {hkdf: {secret_path: SECRET, bytes: 16, inputs: [identity.pnr, issuing_country]}}\n"
	tests := []struct {
		name, derivations, claims string
		// document and opening are the earlier release's output, and
		// opened its opening of the opening claims, in hex, where it opens
		// them.
		document, opening, opened string
	}{
		{
			name:        "an input below a null is absent",
			derivations: "- copy: {input: address.country, output: country}\n",
			claims:      `{"address":null}`,
			document:    `{"address":null}`,
			opening:     `null`,
		},
		{
			name:        "an opening input below a scalar is absent",
			derivations: opening,
			claims:      `{"identity":"x","issuing_country":"SE"}`,
			document:    `{"identity":"x","issuing_country":"SE"}`,
			opening:     `{"issuing_country":"SE"}`,
		},
		{
			name:        "an output below a scalar replaces it",
			derivations: "- copy: {input: given_name, output: name.given}\n",
			claims:      `{"given_name":"Anna","name":"Anna Svensson"}`,
			document:    `{"given_name":"Anna","name":{"given":"Anna"}}`,
			opening:     `null`,
		},
		{
			name:        "a later derivation reads below the object an output put in place of a null",
			derivations: "- copy: {input: given_name, output: identity.given}\n- uppercase: {input: identity.given, output: identity.given_upper}\n",
			claims:      `{"given_name":"Anna","identity":null}`,
			document:    `{"given_name":"Anna","identity":{"given":"Anna","given_upper":"ANNA"}}`,
			opening:     `null`,
		},
		{
			name:        "an input reads the key of the whole name first",
			derivations: "- copy: {input: identity.pnr, output: pnr}\n",
			claims:      `{"identity.pnr":"1","identity":{"pnr":"2"}}`,
			document:    `{"identity.pnr":"1","identity":{"pnr":"2"},"pnr":"1"}`,
			opening:     `null`,
		},
		{
			name:        "an input in place reads the key of the whole name and writes the split name",
			derivations: "- lowercase: {input: identity.country}\n",
			claims:      `{"identity.country":" Sweden "}`,
			document:    `{"identity.country":" Sweden ","identity":{"country":" sweden "}}`,
			opening:     `null`,
		},
		{
			name:        "random keeps the key of the whole name",
			derivations: "- random: {output: identity.document_id}\n",
			claims:      `{"identity.document_id":"ABC"}`,
			document:    `{"identity.document_id":"ABC"}`,
			opening:     `null`,
		},
		{
			name:        "an opening input reads the key of the whole name",
			derivations: opening,
			claims:      `{"identity.pnr":"199001011234","issuing_country":"SE"}`,
			document:    `{"identity.pnr":"199001011234","issuing_country":"SE"}`,
			opening:     `{"identity.pnr":"199001011234","issuing_country":"SE"}`,
			opened:      "cdc2068f38b4e274571acf1fdbcb81c0",
		},
		{
			name:        "an opening input caches a nested claim under the whole name",
			derivations: opening,
			claims:      `{"identity":{"pnr":"199001011234"},"issuing_country":"SE"}`,
			document:    `{"identity":{"pnr":"199001011234"},"issuing_country":"SE"}`,
			opening:     `{"identity.pnr":"199001011234","issuing_country":"SE"}`,
			opened:      "cdc2068f38b4e274571acf1fdbcb81c0",
		},
		{
			name:        "an empty segment of an input is an empty key",
			derivations: "- copy: {input: address..country, output: country}\n",
			claims:      `{"address":{"":{"country":"SE"}}}`,
			document:    `{"address":{"":{"country":"SE"}},"country":"SE"}`,
			opening:     `null`,
		},
		{
			name:        "an empty optional output writes in place",
			derivations: "- trim: {input: identity.country, output: \"\"}\n",
			claims:      `{"identity":{"country":" Sweden "}}`,
			document:    `{"identity":{"country":"Sweden"}}`,
			opening:     `null`,
		},
		{
			name:        "an empty last segment of an output is an empty key",
			derivations: "- copy: {input: given_name, output: name.}\n",
			claims:      `{"given_name":"Anna"}`,
			document:    `{"given_name":"Anna","name":{"":"Anna"}}`,
			opening:     `null`,
		},
	}
	root := repoRoot(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			secret := filepath.Join(dir, "secret.key")
			require.NoError(t, os.WriteFile(secret, []byte("c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M"), 0o600))
			list := strings.Split(strings.TrimSuffix(strings.ReplaceAll(tt.derivations, "SECRET", secret), "\n"), "\n")
			for i, line := range list {
				list[i] = "            " + line
			}
			file := filepath.Join(dir, "config.yaml")
			require.NoError(t, os.WriteFile(file, []byte("common:\n  credential_metadata:\n    pid:\n      format: dc+sd-jwt\n      vctm_file_path: /metadata/vctm_pid.json\napigw:\n  data_sources:\n    assertion:\n      scopes:\n        pid:\n          auth_provider: oidc\n          derivations:\n"+strings.Join(list, "\n")+"\n"), 0o600))
			cfg, err := LoadFile(t.Context(), file, metadataIn(root))
			require.NoError(t, err)

			var claims map[string]any
			require.NoError(t, json.Unmarshal([]byte(tt.claims), &claims))
			src := model.SourceScope{Source: model.DataSourceAssertion, Scope: "pid"}
			openingClaims, err := credential.ApplyScopeDerivations(cfg, src, claims, time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))
			require.NoError(t, err)
			document, err := json.Marshal(claims)
			require.NoError(t, err)
			assert.JSONEq(t, tt.document, string(document), "document")
			got, err := json.Marshal(openingClaims)
			require.NoError(t, err)
			assert.JSONEq(t, tt.opening, string(got), "opening claims")
			if tt.opened == "" {
				return
			}

			shapes, err := cfg.DerivationShapes(src)
			require.NoError(t, err)
			commitment := primitives.HashCommitmentFor(cfg.APIGW.DataSources.DerivationsForSource("pid", model.DataSourceAssertion), claimpath.Keys("eu.europa.ec.eudi.nym_auth.1", "ssc"))
			require.NotNil(t, commitment)
			var cached map[string]any
			require.NoError(t, json.Unmarshal([]byte(tt.opening), &cached))
			opened, err := commitment.NewOpening(cached, shapes.Source)
			require.NoError(t, err)
			assert.Equal(t, tt.opened, hex.EncodeToString(opened), "opening")
		})
	}
}
