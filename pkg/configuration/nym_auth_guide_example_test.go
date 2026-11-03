package configuration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/nymauth"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// guideYAMLBlock returns the n-th fenced yaml block of a markdown file.
func guideYAMLBlock(t *testing.T, path string, n int) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	blocks := strings.Split(string(raw), "```yaml\n")
	require.Greaterf(t, len(blocks), n, "%s has fewer than %d yaml blocks; this test is reading the wrong file", path, n)
	body, _, found := strings.Cut(blocks[n], "```")
	require.Truef(t, found, "%s: yaml block %d is never closed", path, n)
	return body
}

// The operator guide's "Turning it on" block is what a deployment is
// built from, so it has to be configuration this binary accepts.
//
// Not a style point. Until this test existed the block configured
// `verifier_id: verifier.example` - the BARE form, which the same page
// then explains is not a verifier_id and which the loader refuses. An
// operator following the page could not start, and an operator who got
// past it by some other route would have produced pseudonyms no other
// implementation reports.
func TestOperatorGuideExampleIsConfigurationThisBinaryAccepts(t *testing.T) {
	block := guideYAMLBlock(t, filepath.Join("..", "..", "docs", "verifier", "NYM_AUTH_VERIFICATION.md"), 1)

	var cfg model.Cfg
	require.NoError(t, yaml.Unmarshal([]byte(block), &cfg), "the guide's example is not valid YAML")
	require.NotNil(t, cfg.Verifier, "the guide's example no longer configures a verifier")

	// The scope the preset names. The guide says it is a
	// common.credential_metadata entry rather than spelling one out, so
	// the test supplies the one it describes: the mdoc the proof is made
	// over.
	schema := &mdoc.MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "eu.europa.ec.eudi.nym_auth.1",
		Claims: map[string]mdoc.NamespaceClaims{
			"eu.europa.ec.eudi.nym_auth.1": {"secret_seed_commitment": {Mandatory: true, ValueType: "bstr"}},
		},
	}
	cfg.Common = &model.Common{
		CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {Format: "mso_mdoc", MDDL: schema},
		},
	}

	// checkNymAuthVerifier itself is not run: it reads the circuit
	// artifact off disk, and the guide names the path a deployment
	// uses. Its one value that is not a path - the one this page got
	// wrong - is checked directly.
	require.NotNil(t, cfg.Verifier.NymAuth, "the guide's example no longer configures nym_auth")
	require.NoError(t, nymauth.CheckVerifierID(cfg.Verifier.NymAuth.VerifierID),
		"the guide's verifier_id would be refused at startup")
	require.NotEmpty(t, cfg.Verifier.Trust.PDPURL,
		"nym_auth cannot run without a PDP, so the guide must configure one")

	require.NoError(t, checkZkpReqPresetsAskForSomething(&cfg), "the guide's preset asks the wallet for nothing")
	require.NoError(t, checkPresetValidationProfiles(&cfg), "the guide's preset violates the profile the guide recommends")
}
