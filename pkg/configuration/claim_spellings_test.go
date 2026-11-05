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
// holds it, as the earlier release read it at run time, and the checks at
// load accept the files the earlier release loaded. The expected pointers
// are written by hand.
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
			name:    "defaults of which one holds the other",
			dotted:  "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      defaults:\n        address: {country: NO}\n        address.country: SE\n",
			pointer: "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      defaults:\n        - {path: [address], value: {country: NO}}\n        - {path: [address, country], value: SE}\n",
			claim:   func(ds model.DataSources) claimpath.Pointer { return ds.Assertion.Scopes["ehic"].Defaults[1].Path },
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
		{
			name:    "the input of a primitive that read the whole name as one key",
			dotted:  derivations("            - yyyymmdd_to_iso: {input: address.birthdate}\n"),
			pointer: derivations("            - yyyymmdd_to_iso: {input: [address.birthdate]}\n"),
			claim: func(ds model.DataSources) claimpath.Pointer {
				return ds.Presentation.Scopes["nym_auth"].From["pid"].Derivations[0].YYYYMMDDToISO.Input
			},
			want: claimpath.Keys("address.birthdate"),
		},
		{
			name:    "a key a primitive wrote as the whole name, read by a later derivation",
			dotted:  derivations("            - swamid_highest_assurance_level: {input: assurance_level, output: a.b}\n            - copy: {input: a.b, output: birth_date}\n"),
			pointer: derivations("            - swamid_highest_assurance_level: {input: [assurance_level], output: [a.b]}\n            - copy: {input: [a.b], output: [" + nymAuth + ", birth_date]}\n"),
			claim:   copyOf(1, false),
			want:    claimpath.Keys("a.b"),
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

// earlierScope holds the fields of a data source scope the way the earlier
// release decoded them: a map of claims, and a list of derivations.
type earlierScope struct {
	AuthProvider string         `yaml:"auth_provider"`
	Defaults     map[string]any `yaml:"defaults"`
	From         map[string]struct {
		Derivations []map[string]map[string]string `yaml:"derivations"`
	} `yaml:"from"`
}

// earlierDataSources is the part of a configuration file the earlier
// release decoded for the rows below.
type earlierDataSources struct {
	APIGW struct {
		DataSources struct {
			Assertion struct {
				Scopes map[string]earlierScope `yaml:"scopes"`
			} `yaml:"assertion"`
			Presentation struct {
				Scopes map[string]earlierScope `yaml:"scopes"`
			} `yaml:"presentation"`
		} `yaml:"data_sources"`
	} `yaml:"apigw"`
}

// A file with an alias, a merge key or a repeated key loads as its twin
// written out by hand does. gopkg.in/yaml.v2 decodes both equal into the
// earlier release's types: an alias stands for its node in the role where
// it stands, a merge key adds the entries of its mappings, and a key a
// struct repeats adds to a struct or a map. Each warning names the line
// that holds the spelling.
func TestAliasesMergeKeysAndRepeatedKeysLoadAsYAMLv2ReadsThem(t *testing.T) {
	const assertion = "apigw:\n  data_sources:\n    assertion:\n      scopes:\n"
	const presentation = "apigw:\n  data_sources:\n    presentation:\n      scopes:\n        nym_auth:\n          from:\n"
	tests := []struct {
		name, file, twin string
		lines            []int
	}{
		{
			name:  "an alias of an anchor outside the claims",
			file:  "x-defaults: &defaults\n  address.country: SE\n" + assertion + "        ehic:\n          auth_provider: oidc\n          defaults: *defaults\n",
			twin:  assertion + "        ehic:\n          auth_provider: oidc\n          defaults:\n            address.country: SE\n",
			lines: []int{2},
		},
		{
			name:  "an alias read in the roles of two credentials",
			file:  presentation + "            pid:\n              derivations: &derivations\n                - copy: {input: a.b.c, output: x}\n            pid_mdoc:\n              derivations: *derivations\n",
			twin:  presentation + "            pid:\n              derivations:\n                - copy: {input: a.b.c, output: x}\n            pid_mdoc:\n              derivations:\n                - copy: {input: a.b.c, output: x}\n",
			lines: []int{9, 9, 9, 9},
		},
		{
			name:  "a merge key in a map of claims",
			file:  "x-defaults: &defaults\n  address.country: SE\n" + assertion + "        ehic:\n          auth_provider: oidc\n          defaults: {<<: *defaults, issuing_authority: X}\n",
			twin:  assertion + "        ehic:\n          auth_provider: oidc\n          defaults:\n            address.country: SE\n            issuing_authority: X\n",
			lines: []int{2, 9},
		},
		{
			name:  "a merge key in a scope that sets the map of claims again",
			file:  assertion + "        ehic: &ehic\n          auth_provider: oidc\n          defaults:\n            address.country: SE\n        pid:\n          <<: *ehic\n          defaults:\n            issuing_authority: X\n",
			twin:  assertion + "        ehic:\n          auth_provider: oidc\n          defaults:\n            address.country: SE\n        pid:\n          auth_provider: oidc\n          defaults:\n            address.country: SE\n            issuing_authority: X\n",
			lines: []int{8, 8, 12},
		},
		{
			name:  "a key a struct repeats",
			file:  assertion + "        ehic:\n          auth_provider: oidc\n          defaults:\n            address.country: SE\n" + assertion + "        pid:\n          auth_provider: oidc\n          defaults:\n            issuing_authority: X\n",
			twin:  assertion + "        ehic:\n          auth_provider: oidc\n          defaults:\n            address.country: SE\n        pid:\n          auth_provider: oidc\n          defaults:\n            issuing_authority: X\n",
			lines: []int{8, 16},
		},
		{
			name:  "a key a map repeats",
			file:  assertion + "        ehic:\n          auth_provider: oidc\n          defaults:\n            address.country: SE\n        ehic:\n          defaults:\n            issuing_authority: X\n",
			twin:  assertion + "        ehic:\n          defaults:\n            issuing_authority: X\n",
			lines: []int{11},
		},
		{
			name:  "a merge key and an alias no field reads",
			file:  "x-defaults: &defaults\n  address.country: SE\nx-unread:\n  <<: 1\n  self: &self [*self]\n" + assertion + "        ehic:\n          auth_provider: oidc\n          defaults: *defaults\n",
			twin:  assertion + "        ehic:\n          auth_provider: oidc\n          defaults:\n            address.country: SE\n",
			lines: []int{2},
		},
		{
			name:  "a block scalar the alias moves",
			file:  "x-defaults: &defaults\n  note: |\n    line one\n      line two\n  address.country: SE\n" + assertion + "        ehic:\n          auth_provider: oidc\n          defaults: *defaults\n",
			twin:  assertion + "        ehic:\n          auth_provider: oidc\n          defaults:\n            note: \"line one\\n  line two\\n\"\n            address.country: SE\n",
			lines: []int{2, 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var earlier, earlierTwin earlierDataSources
			require.NoError(t, yaml.Unmarshal([]byte(tt.file), &earlier))
			require.NoError(t, yaml.Unmarshal([]byte(tt.twin), &earlierTwin))
			require.Equal(t, earlierTwin, earlier, "the twin is the file gopkg.in/yaml.v2 reads")

			got, rewrites, err := decodeDataSources("aliases.yaml", []byte(tt.file), rolesCfg())
			require.NoError(t, err)
			want, _, err := decodeDataSources("twin.yaml", []byte(tt.twin), rolesCfg())
			require.NoError(t, err)
			assert.Equal(t, want, got)
			lines := make([]int, len(rewrites))
			for i, rewrite := range rewrites {
				lines[i] = rewrite.Line
			}
			assert.Equal(t, tt.lines, lines)
		})
	}
}

// earlierTemplates is the part of a presentation request file the earlier
// release decoded for the rows below, in its types: a claim path is a list
// of strings and nulls, and claim_mappings a map.
type earlierTemplates struct {
	Templates []struct {
		ID   string `yaml:"id"`
		DCQL struct {
			Credentials []struct {
				ID     string `yaml:"id"`
				Format string `yaml:"format"`
				Claims []struct {
					Path []*string `yaml:"path"`
				} `yaml:"claims"`
			} `yaml:"credentials"`
		} `yaml:"dcql"`
		ClaimMappings map[string]string `yaml:"claim_mappings"`
	} `yaml:"templates"`
}

// A presentation request file with an alias, a merge key or a repeated key
// loads as its twin written out by hand does, which gopkg.in/yaml.v2 reads
// as the same templates. A credential query reads its own mappings: the
// claims a merge key sets are upgraded, and a key it repeats refuses the
// file, as gopkg.in/yaml.v2 refuses it. Each warning names the line that
// holds the spelling.
func TestTemplateAliasesLoadAsYAMLv2ReadsThem(t *testing.T) {
	const template = "templates:\n  - id: age\n    oidc_scopes: [age]\n    dcql:\n      credentials:\n        - %s\n    claim_mappings:%s\n"
	const query = "id: age\n          format: dc+sd-jwt\n          claims:\n            - path: [age_over_18]"
	const mappings = "\n      age_over_18: age_over_18"
	tests := []struct {
		name, file, twin string
		lines            []int
		// refused is the error gopkg.in/yaml.v2 refuses the file with.
		refused string
	}{
		{
			name:  "an alias of the claim mappings",
			file:  "x-mappings: &mappings\n  age_over_18: age_over_18\n" + fmt.Sprintf(template, query, " *mappings"),
			twin:  fmt.Sprintf(template, query, mappings),
			lines: []int{12},
		},
		{
			name:  "claims a merge key sets in a credential query",
			file:  "x-claims: &claims\n  claims:\n    - path: [name_by_language, no]\n" + fmt.Sprintf(template, "<<: *claims\n          id: age\n          format: dc+sd-jwt", mappings),
			twin:  fmt.Sprintf(template, "id: age\n          format: dc+sd-jwt\n          claims:\n            - path: [name_by_language, no]", mappings),
			lines: []int{3, 12},
		},
		{
			name:    "a key a credential query repeats",
			file:    fmt.Sprintf(template, "id: other\n          "+query, mappings),
			refused: "credential query: id is named more than once, and YAML keeps only the last",
		},
	}
	load := func(text string) (*PresentationRequestConfig, error) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "templates.yaml"), []byte(text), 0o600))
		return LoadPresentationRequests(t.Context(), dir)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.refused != "" {
				var read PresentationRequestConfig
				require.ErrorContains(t, yaml.Unmarshal([]byte(tt.file), &read), tt.refused)
				_, err := load(tt.file)
				require.ErrorContains(t, err, tt.refused)
				return
			}
			var earlier, earlierTwin earlierTemplates
			require.NoError(t, yaml.Unmarshal([]byte(tt.file), &earlier))
			require.NoError(t, yaml.Unmarshal([]byte(tt.twin), &earlierTwin))
			require.Equal(t, earlierTwin, earlier, "the twin is the file gopkg.in/yaml.v2 reads")

			got, err := load(tt.file)
			require.NoError(t, err)
			want, err := load(tt.twin)
			require.NoError(t, err)
			assert.Equal(t, want.Templates, got.Templates)
			lines := make([]int, len(got.Deprecations))
			for i, deprecation := range got.Deprecations {
				lines[i] = deprecation.Line
			}
			assert.Equal(t, tt.lines, lines)
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
