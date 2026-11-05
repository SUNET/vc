package configuration

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/legacyclaims"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// The upgrade reads each dotted claim name in the shape of the role that
// holds it, as the earlier release read it at run time. The expected
// pointers are written by hand.
func TestUpgradeReadsEachRoleAsTheEarlierReleaseDid(t *testing.T) {
	const nymAuth = "eu.europa.ec.eudi.nym_auth.1"
	presentation := func(from, claims string) string {
		return "presentation:\n  scopes:\n    nym_auth:\n      from:\n        " + from + ":\n" + claims
	}
	derivations := func(list string) string {
		return presentation("pid", "          derivations:\n"+list)
	}
	requiredClaim := func(ds model.DataSources) claimpath.Pointer {
		for _, accepted := range ds.Presentation.Scopes["nym_auth"].From {
			return accepted.RequiredClaims[0].Path
		}
		return claimpath.Pointer{}
	}
	copyOf := func(i int, output bool) func(model.DataSources) claimpath.Pointer {
		return func(ds model.DataSources) claimpath.Pointer {
			c := ds.Presentation.Scopes["nym_auth"].From["pid"].Derivations[i].Copy
			if output {
				return c.Output
			}
			return c.Input
		}
	}

	tests := []struct {
		name            string
		dotted, pointer string
		claim           func(model.DataSources) claimpath.Pointer
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
			claim:   func(ds model.DataSources) claimpath.Pointer { return ds.Assertion.Scopes["ehic"].Defaults[0].Path },
			want:    claimpath.Keys("address", "country"),
		},
		{
			name:    "an element an mdoc document's MDDL declares",
			dotted:  derivations("            - copy: {input: birthdate, output: birth_date}\n"),
			pointer: derivations("            - copy: {input: [birthdate], output: [" + nymAuth + ", birth_date]}\n"),
			claim:   copyOf(0, true),
			want:    claimpath.Keys(nymAuth, "birth_date"),
		},
		{
			name:    "a dotted key an mdoc document's MDDL does not declare",
			dotted:  derivations("            - copy: {input: birthdate, output: a.b}\n"),
			pointer: derivations("            - copy: {input: [birthdate], output: [a, b]}\n"),
			claim:   copyOf(0, true),
			want:    claimpath.Keys("a", "b"),
		},
		{
			name:    "a derivation input an earlier derivation writes",
			dotted:  derivations("            - copy: {input: birthdate, output: a.b}\n            - copy: {input: a.b, output: birth_date}\n"),
			pointer: derivations("            - copy: {input: [birthdate], output: [a, b]}\n            - copy: {input: [a, b], output: [" + nymAuth + ", birth_date]}\n"),
			claim:   copyOf(1, false),
			want:    claimpath.Keys("a", "b"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for form, dataSources := range map[string]string{"dotted": tt.dotted, "pointer": tt.pointer} {
				cfg := rolesCfg()
				sources, _, err := decodeDataSources("roles.yaml", dataSourcesFile(dataSources), cfg)
				require.NoError(t, err, form)
				cfg.APIGW = &model.APIGW{DataSources: sources}
				require.NoError(t, cfg.CheckClaimPaths(), form)
				assert.Equal(t, tt.want, tt.claim(sources), form)
			}
		})
	}
}

// rolesCfg holds the credentials the role table's claims belong to.
func rolesCfg() *model.Cfg {
	declares := func(namespace string, elements ...string) *mdoc.MDDLSchema {
		claims := mdoc.NamespaceClaims{}
		for _, element := range elements {
			claims[element] = mdoc.ClaimMetadata{}
		}
		return &mdoc.MDDLSchema{Claims: map[string]mdoc.NamespaceClaims{namespace: claims}}
	}
	return &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		"pid":      {Format: "dc+sd-jwt"},
		"ehic":     {Format: "dc+sd-jwt"},
		"pid_mdoc": {Format: "mso_mdoc", MDDL: declares("eu.europa.ec.eudi.pid.1", "birth_date", "given_name")},
		"nym_auth": {Format: "mso_mdoc", MDDL: declares("eu.europa.ec.eudi.nym_auth.1", "birth_date")},
	}}}
}

// dataSourcesFile is a configuration file holding dataSources under
// apigw.data_sources.
func dataSourcesFile(dataSources string) []byte {
	lines := strings.Split(strings.TrimSuffix(dataSources, "\n"), "\n")
	for i, line := range lines {
		lines[i] = "    " + line
	}
	return []byte("apigw:\n  data_sources:\n" + strings.Join(lines, "\n") + "\n")
}

// Each file of testdata/legacy is the earlier release's version of the
// in-repo file at the same path, which holds the same configuration or
// templates in the current spellings. Both load, or both are refused
// alike, and they load equal. A template's claim_mappings is left out: the
// keyed form maps each presentation through its own query, and
// TestClaimsExtractor_MapClaimsToOIDC covers the earlier form.
func TestTheEarlierReleaseFilesLoad(t *testing.T) {
	root := repoRoot(t)
	legacyDir := filepath.Join("testdata", "legacy")
	var files []string
	require.NoError(t, filepath.WalkDir(legacyDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(legacyDir, path)
		files = append(files, filepath.ToSlash(rel))
		return err
	}))
	require.NotEmpty(t, files)

	for _, rel := range files {
		t.Run(rel, func(t *testing.T) {
			legacy, current := filepath.Join(legacyDir, rel), filepath.Join(root, rel)
			if slices.Contains(shippedConfigs, rel) {
				legacyCfg, err := LoadFile(t.Context(), legacy, metadataIn(root))
				require.NoError(t, err)
				currentCfg, err := LoadFile(t.Context(), current, metadataIn(root))
				require.NoError(t, err)
				legacyCfg.Deprecations, currentCfg.Deprecations = nil, nil
				assert.Equal(t, currentCfg, legacyCfg)
				return
			}
			legacyTemplates, legacyErr := loadTemplates(legacy)
			currentTemplates, currentErr := loadTemplates(current)
			if legacyErr != nil {
				require.Error(t, currentErr)
				assert.Equal(t, strings.ReplaceAll(legacyErr.Error(), legacy, "FILE"), strings.ReplaceAll(currentErr.Error(), current, "FILE"))
				return
			}
			require.NoError(t, currentErr)
			assert.Equal(t, currentTemplates, legacyTemplates)
		})
	}
	t.Logf("%d files of the earlier release load", len(files))
}

// metadataIn maps the deployment schema paths /metadata/... of the in-repo
// configurations to the metadata directory of the repository at root.
func metadataIn(root string) func(string) string {
	return func(path string) string {
		if rest, ok := strings.CutPrefix(path, "/metadata/"); ok {
			return filepath.Join(root, "metadata", rest)
		}
		return path
	}
}

// loadTemplates loads a template file as the verifier does, with each
// template's claim_mappings cleared.
func loadTemplates(path string) ([]*PresentationRequestTemplate, error) {
	file, err := loadTemplateFile(path)
	if err != nil {
		return nil, err
	}
	config := PresentationRequestConfig{Templates: file.templates}
	if err := config.check(); err != nil {
		return nil, err
	}
	for _, template := range file.templates {
		template.ClaimMappings = openid4vp.ClaimMappings{}
	}
	return file.templates, nil
}

// Loading warns once per claim spelling of the earlier release: the
// warnings name exactly the lines the fixture marks "# legacy".
func TestLoadingWarnsOncePerLegacySpelling(t *testing.T) {
	root := repoRoot(t)
	for file, load := range map[string]func(string) ([]legacyclaims.Rewrite, error){
		"testdata/legacy_spellings.yaml": func(path string) ([]legacyclaims.Rewrite, error) {
			cfg, err := LoadFile(t.Context(), path, metadataIn(root))
			if err != nil {
				return nil, err
			}
			return cfg.Deprecations, nil
		},
		"testdata/legacy_spellings_template.yaml": func(path string) ([]legacyclaims.Rewrite, error) {
			file, err := loadTemplateFile(path)
			return file.deprecations, err
		},
	} {
		t.Run(file, func(t *testing.T) {
			rewrites, err := load(file)
			require.NoError(t, err)
			var warnings []string
			legacyclaims.Warn(&logger.Log{Logger: funcr.New(func(_, args string) { warnings = append(warnings, args) }, funcr.Options{})}, rewrites)
			require.Len(t, warnings, len(rewrites))

			src, err := os.ReadFile(file)
			require.NoError(t, err)
			var marked, warned []int
			for i, line := range strings.Split(string(src), "\n") {
				if strings.HasSuffix(line, "# legacy") {
					marked = append(marked, i+1)
				}
			}
			for _, rewrite := range rewrites {
				warned = append(warned, rewrite.Line)
			}
			slices.Sort(warned)
			require.NotEmpty(t, marked)
			assert.Equal(t, marked, warned)
		})
	}
}

// Decoding reads the document of a stream that gopkg.in/yaml.v2 reads: a
// file with the earlier spelling decodes equal to yaml.v2's reading of the
// file with the current spelling.
func TestDecodeReadsTheDocumentYAMLv2Reads(t *testing.T) {
	const mapping = "apigw:\n  auth_providers:\n    oidc:\n      attribute_mapping:\n        birthdate:\n          claim: %s\n"
	earlier, current := fmt.Sprintf(mapping, "birthdate"), fmt.Sprintf(mapping, "[birthdate]")
	const other = "apigw:\n  public_url: https://other.example\n"
	for name, stream := range map[string]func(document string) string{
		"one document":           func(d string) string { return d },
		"comments before ---":    func(d string) string { return "# comment\n---\n" + d },
		"two documents":          func(d string) string { return d + "---\n" + other },
		"a document of comments": func(d string) string { return "---\n# comment\n---\n" + d },
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(stream(earlier)), 0o600))
			got, err := DecodeFile(t.Context(), path, nil)
			require.NoError(t, err)
			want := &model.Cfg{}
			require.NoError(t, yaml.Unmarshal([]byte(stream(current)), want))
			got.Deprecations = nil
			assert.Equal(t, want, got)
		})
	}
}

// A binding attribute of the earlier release, a dotted name, reads as one
// key per segment, as the verifier split it. A binding attribute that
// selects every element of an array is refused.
func TestBindingAttributesReadAsTheEarlierReleaseDid(t *testing.T) {
	const binding = "verifier:\n  combined_presentation:\n    binding_attributes:\n      - paths: %s\n"
	decode := func(paths string) (*model.Cfg, error) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf(binding, paths)), 0o600))
		cfg, err := DecodeFile(t.Context(), path, nil)
		if err != nil {
			return nil, err
		}
		return cfg, cfg.CheckClaimPaths()
	}

	cfg, err := decode("[family_name, place_of_birth.locality]")
	require.NoError(t, err)
	want := []claimpath.Pointer{claimpath.Keys("family_name"), claimpath.Keys("place_of_birth", "locality")}
	assert.Equal(t, want, cfg.Verifier.CombinedPresentation.BindingAttributes[0].Paths)

	_, err = decode("[[nationalities, null]]")
	require.ErrorContains(t, err, "verifier.combined_presentation.binding_attributes[0].paths[0]: ")
	require.ErrorContains(t, err, "selects every element of an array")
}

// A string where the earlier release read an array, such as a DCQL claims
// path, reaches the strict decoder, which refuses it.
func TestStringPointerRefusedWhereNoNameWasRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "template.yaml")
	require.NoError(t, os.WriteFile(path, []byte("id: t\ndcql:\n  credentials:\n    - id: pid\n      format: dc+sd-jwt\n      claims:\n        - path: given_name\nclaim_mappings: \"*\"\n"), 0o600))
	_, err := loadTemplateFile(path)
	var refused *claimpath.StringError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, "given_name", refused.Text)
}
