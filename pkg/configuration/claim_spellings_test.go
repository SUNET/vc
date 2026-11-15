package configuration

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

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
// load accept the files the earlier release loaded. A role that looked the
// whole name up as one top-level key first carries the name beside the
// pointer. The expected pointers and names are written by hand.
func TestUpgradeReadsEachRoleAsTheEarlierReleaseDid(t *testing.T) {
	const nymAuth = "eu.europa.ec.eudi.nym_auth.1"
	presentation := func(from, claims string) string {
		return "presentation:\n  scopes:\n    nym_auth:\n      from:\n        " + from + ":\n" + claims
	}
	derivations := func(list string) string {
		return presentation("pid", "          derivations:\n"+list)
	}
	requiredClaim := func(ds model.DataSources) claimpath.Ref {
		for _, accepted := range ds.Presentation.Scopes["nym_auth"].From {
			return accepted.RequiredClaims[0].Path
		}
		return claimpath.Ref{}
	}
	copyOf := func(i int, output bool) func(model.DataSources) claimpath.Ref {
		return func(ds model.DataSources) claimpath.Ref {
			c := ds.Presentation.Scopes["nym_auth"].From["pid"].Derivations[i].Copy
			if output {
				return claimpath.Ref{Path: c.Output}
			}
			return c.Input
		}
	}

	tests := []struct {
		name   string
		dotted string
		// pointer is the claim in the current spelling. It is empty where
		// the upgrade carries the name: a file writes no such claim.
		pointer string
		claim   func(model.DataSources) claimpath.Ref
		want    claimpath.Pointer
		// carried is the name the upgrade carries beside the pointer.
		carried string
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
			claim:   requiredClaim,
			want:    claimpath.Keys("org.iso.18013.5.1", "given_name"),
			carried: "given_name",
		},
		{
			name:    "a claim of a JSON-based document",
			dotted:  "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      defaults:\n        address.country: SE\n",
			pointer: "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      defaults:\n        - {path: [address, country], value: SE}\n",
			claim: func(ds model.DataSources) claimpath.Ref {
				return claimpath.Ref{Path: ds.Assertion.Scopes["ehic"].Defaults[0].Path}
			},
			want: claimpath.Keys("address", "country"),
		},
		{
			name:    "defaults of which one holds the other",
			dotted:  "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      defaults:\n        address: {country: NO}\n        address.country: SE\n",
			pointer: "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      defaults:\n        - {path: [address], value: {country: NO}}\n        - {path: [address, country], value: SE}\n",
			claim: func(ds model.DataSources) claimpath.Ref {
				return claimpath.Ref{Path: ds.Assertion.Scopes["ehic"].Defaults[1].Path}
			},
			want: claimpath.Keys("address", "country"),
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
			claim:   copyOf(1, false),
			want:    claimpath.Keys("a", "b"),
			carried: "a.b",
		},
		{
			name:    "the input of a primitive that read the whole name as one key",
			dotted:  derivations("            - yyyymmdd_to_iso: {input: address.birthdate}\n"),
			pointer: derivations("            - yyyymmdd_to_iso: {input: [address.birthdate]}\n"),
			claim: func(ds model.DataSources) claimpath.Ref {
				return ds.Presentation.Scopes["nym_auth"].From["pid"].Derivations[0].YYYYMMDDToISO.Input
			},
			want: claimpath.Keys("address.birthdate"),
		},
		{
			name:    "a key a primitive wrote as the whole name, read by a later derivation",
			dotted:  derivations("            - swamid_highest_assurance_level: {input: assurance_level, output: a.b}\n            - copy: {input: a.b, output: birth_date}\n"),
			claim:   copyOf(1, false),
			want:    claimpath.Keys("a", "b"),
			carried: "a.b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for form, dataSources := range map[string]string{"dotted": tt.dotted, "pointer": tt.pointer} {
				if dataSources == "" {
					continue
				}
				cfg := rolesCfg()
				sources, _, err := decodeDataSources("roles.yaml", dataSourcesFile(dataSources), cfg)
				require.NoError(t, err, form)
				cfg.APIGW = &model.APIGW{DataSources: sources}
				require.NoError(t, cfg.CheckClaimPaths(), form)
				claim := tt.claim(sources)
				assert.Equal(t, tt.want, claim.Path, form)
				carried, _ := claim.Dotted()
				assert.Equal(t, tt.carried, carried, form)
			}
		})
	}
}

// The earlier release read the entries of a required_claims and of a
// document_claims map in name order. Its DCQL query asked for the claims in
// that order, and of two entries that write one claim, the later by name
// set it. The upgrade lists the entries in that order.
func TestUpgradeListsAMapInNameOrder(t *testing.T) {
	const pid = "eu.europa.ec.eudi.pid.1"
	sources, _, err := decodeDataSources("order.yaml", dataSourcesFile(
		"datastore:\n  scopes:\n    ehic:\n      auth_provider: openid4vp\n      auth_scopes:\n        pid:\n          auth_claims: [[given_name]]\n"+
			"          document_claims:\n            family_name: x_copy\n            birthdate: x_copy\n"+
			"presentation:\n  scopes:\n    nym_auth:\n      from:\n        pid_mdoc:\n          required_claims:\n"+
			"            "+pid+".issuing_country: []\n            "+pid+".birth_date: []\n            "+pid+".administrative_number: []\n"), rolesCfg())
	require.NoError(t, err)

	assert.Equal(t, model.DocumentClaims{
		{From: claimpath.Keys("birthdate"), To: claimpath.Keys("x_copy")},
		{From: claimpath.Keys("family_name"), To: claimpath.Keys("x_copy")},
	}, sources.Datastore.Scopes["ehic"].AuthScopes["pid"].DocumentClaims)
	var required []claimpath.Pointer
	for _, claim := range sources.Presentation.Scopes["nym_auth"].From["pid_mdoc"].RequiredClaims {
		required = append(required, claim.Path.Path)
	}
	assert.Equal(t, []claimpath.Pointer{
		claimpath.Keys(pid, "administrative_number"),
		claimpath.Keys(pid, "birth_date"),
		claimpath.Keys(pid, "issuing_country"),
	}, required)
}

// The loader refuses a file that writes the mapping {dotted, path}, its
// own form of an upgraded dotted name, at each claim that decodes it, and
// through an alias that stands for it.
func TestAFileWritesNoUpgradedName(t *testing.T) {
	const presented = "presentation:\n  scopes:\n    nym_auth:\n      from:\n        pid_mdoc:\n          required_claims:\n"
	tests := []struct{ name, dataSources string }{
		{
			name:        "a derivation input",
			dataSources: "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      derivations:\n        - copy: {input: {dotted: a.b, path: [a, b]}, output: [c]}\n",
		},
		{
			name:        "a derivation input of a presented credential",
			dataSources: presented + "            - path: [eu.europa.ec.eudi.pid.1, given_name]\n          derivations:\n            - copy: {input: {dotted: given_name, path: [eu.europa.ec.eudi.pid.1, given_name]}, output: [eu.europa.ec.eudi.nym_auth.1, given_name]}\n",
		},
		{
			name:        "a required claim",
			dataSources: presented + "            - path: {dotted: given_name, path: [eu.europa.ec.eudi.pid.1, given_name]}\n",
		},
		{
			name:        "an alias",
			dataSources: "assertion:\n  scopes:\n    ehic:\n      auth_provider: oidc\n      x-claim: &claim {dotted: a.b, path: [a, b]}\n      derivations:\n        - copy: {input: *claim, output: [c]}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeDataSources("names.yaml", dataSourcesFile(tt.dataSources), rolesCfg())
			require.ErrorIs(t, err, legacyclaims.ErrUpgradedRef)
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

// Loading warns once per type metadata claim path key that some readers
// read as the earlier release did: name[i], "*" and "null", in the claims
// and path members encoding/json fills, once for two scopes that load the
// same file. The expected records are derived by hand from the text.
func TestLoadingWarnsOncePerVCTMKeyReadTwoWays(t *testing.T) {
	dir := t.TempDir()
	vctm := filepath.Join(dir, "vctm.json")
	require.NoError(t, os.WriteFile(vctm, []byte(`{
  "vct": "urn:example:1",
  "claims": [{"path": ["unread[0]"]}],
  "Claims": [
    {"path": ["a", "b[2]", "c"]},
    {"path": ["d", "*"]},
    {"path": ["e", "null"], "Path": ["e",
      "f[0]"]},
    {"path": ["g[-1]", "h[x]", "i[1", "*x", "nul"]}
  ]
}
`), 0o600))
	config := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(config, []byte("common:\n  credential_metadata:\n    one: {format: dc+sd-jwt, vctm_file_path: "+vctm+"}\n    two: {format: dc+sd-jwt, vctm_file_path: "+vctm+"}\n"), 0o600))

	cfg, err := LoadFile(t.Context(), config, nil)
	require.NoError(t, err)
	type record struct {
		File, Path, Old, New string
		Line                 int
	}
	var got []record
	for _, r := range cfg.Deprecations {
		got = append(got, record{File: r.File, Path: r.Path, Old: r.Old, New: r.New, Line: r.Line})
	}
	assert.Equal(t, []record{
		{File: vctm, Path: "$.claims[0].path[1]", Old: `"b[2]"`, New: `"b", 2`, Line: 5},
		{File: vctm, Path: "$.claims[1].path[1]", Old: `"*"`, New: "null", Line: 6},
		{File: vctm, Path: "$.claims[2].path[1]", Old: `"f[0]"`, New: `"f", 0`, Line: 8},
	}, got)
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

// gopkg.in/yaml.v2 reads one document from a file with any of its line
// breaks (CRLF, CR, LF, NEL, LS and PS), after a UTF-8 byte order mark,
// and in UTF-16 after a UTF-16 byte order mark. A file of the earlier
// release loads and warns in each such form as its LF UTF-8 text does, and
// migrate_claim_paths writes the form of its input. The alias of
// aliased.yaml makes the upgrade read the text yaml.v2 decodes.
func TestEachLineBreakAndEncodingLoadsAsLF(t *testing.T) {
	root := repoRoot(t)
	forms := map[string]func([]byte) []byte{
		"CR":   lineBreaks("\r"),
		"CRLF": lineBreaks("\r\n"),
		"NEL":  lineBreaks("\xc2\x85"),
		"LS":   lineBreaks("\xe2\x80\xa8"),
		"PS":   lineBreaks("\xe2\x80\xa9"),
		"CRLF on each line that holds a comment": func(text []byte) []byte {
			lines := strings.SplitAfter(string(text), "\n")
			for i, line := range lines {
				if strings.Contains(line, "#") {
					lines[i] = strings.Replace(line, "\n", "\r\n", 1)
				}
			}
			return []byte(strings.Join(lines, ""))
		},
		"a UTF-8 byte order mark and CRLF": func(text []byte) []byte { return append([]byte("\xef\xbb\xbf"), lineBreaks("\r\n")(text)...) },
		"UTF-16LE and CR":                  func(text []byte) []byte { return utf16Text(binary.LittleEndian, lineBreaks("\r")(text)) },
		"UTF-16BE":                         func(text []byte) []byte { return utf16Text(binary.BigEndian, text) },
	}
	const aliased = "# The provider is an alias.\nx-provider: &provider oidc\ncommon:\n  credential_metadata:\n    pid:\n      format: dc+sd-jwt\n      vctm_file_path: /metadata/vctm_pid.json\napigw:\n  data_sources:\n    assertion:\n      scopes:\n        pid:\n          auth_provider: *provider # the provider\n          defaults:\n            address.country: SE # legacy\n          derivations:\n            - copy: {input: given_name, output: name} # legacy\n"
	loadConfig := func(path string) (any, error) {
		cfg, err := LoadFile(t.Context(), path, metadataIn(root))
		if err != nil {
			return nil, err
		}
		for i := range cfg.Deprecations {
			cfg.Deprecations[i].File = ""
		}
		return cfg, nil
	}
	convertConfig := func(path string, src []byte) ([]byte, error) {
		text, _, err := UpgradeFile(t.Context(), path, src, metadataIn(root))
		return text, err
	}
	loadTemplates := func(path string) (any, error) {
		file, err := loadTemplateFile(path)
		for i := range file.deprecations {
			file.deprecations[i].File = ""
		}
		return file, err
	}
	convertTemplates := func(path string, src []byte) ([]byte, error) {
		text, _, err := UpgradeTemplateFile(path, src)
		return text, err
	}
	readFixture := func(name string) []byte {
		src, err := os.ReadFile(filepath.Join("testdata", name))
		require.NoError(t, err)
		return src
	}
	files := []struct {
		name    string
		text    []byte
		load    func(path string) (any, error)
		convert func(path string, src []byte) ([]byte, error)
	}{
		{"legacy_spellings.yaml", readFixture("legacy_spellings.yaml"), loadConfig, convertConfig},
		{"legacy_spellings_template.yaml", readFixture("legacy_spellings_template.yaml"), loadTemplates, convertTemplates},
		{"aliased.yaml", []byte(aliased), loadConfig, convertConfig},
	}
	for _, file := range files {
		lf := filepath.Join(t.TempDir(), file.name)
		require.NoError(t, os.WriteFile(lf, file.text, 0o600))
		want, err := file.load(lf)
		require.NoError(t, err)
		converted, err := file.convert(lf, file.text)
		require.NoError(t, err)
		require.NotEqual(t, file.text, converted)
		for name, form := range forms {
			t.Run(file.name+"/"+name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), file.name)
				src := form(file.text)
				require.NoError(t, os.WriteFile(path, src, 0o600))
				got, err := file.load(path)
				require.NoError(t, err)
				assert.Equal(t, want, got)
				text, err := file.convert(path, src)
				require.NoError(t, err)
				assert.Equal(t, string(form(converted)), string(text))
			})
		}
	}
}

// lineBreaks returns a function that writes each LF of a text as
// lineBreak.
func lineBreaks(lineBreak string) func([]byte) []byte {
	return func(text []byte) []byte { return bytes.ReplaceAll(text, []byte("\n"), []byte(lineBreak)) }
}

// utf16Text writes a UTF-8 text in UTF-16 after its byte order mark.
func utf16Text(order binary.AppendByteOrder, text []byte) []byte {
	out := order.AppendUint16(nil, 0xfeff)
	for _, unit := range utf16.Encode([]rune(string(text))) {
		out = order.AppendUint16(out, unit)
	}
	return out
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

// A presentation request file with an alias or a merge key loads as its
// twin written out by hand does, which gopkg.in/yaml.v2 reads as the same
// templates. A credential query reads its own mappings: the claims a merge
// key sets are upgraded. Each warning names the line that holds the
// spelling.
func TestTemplateAliasesLoadAsYAMLv2ReadsThem(t *testing.T) {
	const template = "templates:\n  - id: age\n    oidc_scopes: [age]\n    dcql:\n      credentials:\n        - %s\n    claim_mappings:%s\n"
	const query = "id: age\n          format: dc+sd-jwt\n          claims:\n            - path: [age_over_18]"
	const mappings = "\n      age_over_18: age_over_18"
	tests := []struct {
		name, file, twin string
		lines            []int
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
	}
	load := func(text string) (*PresentationRequestConfig, error) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "templates.yaml"), []byte(text), 0o600))
		return LoadPresentationRequests(t.Context(), dir)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

// A template whose credential query the decoder keeps as written loads,
// and holds the dcql gopkg.in/yaml.v2 reads from it: a query that is no
// mapping, claims that are no list, an id that is no scalar, and a
// multiple that is no boolean.
func TestCredentialQueriesKeptAsWrittenLoad(t *testing.T) {
	const template = "templates:\n  - id: age\n    oidc_scopes: [age]\n    dcql:\n      credentials:\n        - %s\n"
	for _, query := range []string{
		"x",
		"{id: age, format: dc+sd-jwt, claims: {age_over_18: {}}}",
		"{id: [age], format: dc+sd-jwt, claims: [{path: [age_over_18]}]}",
		"{id: age, format: dc+sd-jwt, multiple: maybe, claims: [{path: [age_over_18]}]}",
	} {
		t.Run(query, func(t *testing.T) {
			var read PresentationRequestConfig
			require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf(template, query)), &read))
			got, err := loadTemplateText(t, template, query)
			require.NoError(t, err)
			assert.Equal(t, read.Templates[0].DCQLQuery, got.Templates[0].DCQLQuery)
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

// A file that fails to decode as a list of templates loads one template
// from its top-level keys, and names the error of the list. Each row holds
// the id, the scopes and the query of the template a run of the earlier
// release loaded from the file.
func TestListThatFailsToDecodeLoadsTheTopLevelKeys(t *testing.T) {
	const entry = "templates:\n  - id: t1\n    oidc_scopes: [s1]\n    dcql:\n      credentials:\n        - id: q1\n          format: dc+sd-jwt\n          claims:\n            - path: %s\n    claim_mappings:\n      given_name: given_name\n    enabled: %s\n"
	const top = "id: top\noidc_scopes: [stop]\n"
	const alias = "x-meta: &meta\n  vct_values: [urn:x]\ntemplates:\n  - id: t1\n    dcql:\n      credentials:\n        - id: q1\n          meta: *meta\n          claims:\n            - path: []\n"
	const queryTop = "dcql:\n  credentials:\n    - id: q0\n      format: dc+sd-jwt\n      meta: {vct_values: [urn:x]}\n      claims:\n        - path: [place_of_birth, locality]\nclaim_mappings:\n  place_of_birth.locality: locality\n"
	tests := []struct {
		name, file string
		id         string
		scopes     []string
		// query is the JSON of the template's dcql; empty for none.
		query string
		// fault is the part of the list's error that names the fault.
		fault string
	}{
		{name: "an empty claims path", file: fmt.Sprintf(entry, "[]", "true"), fault: "non-empty array"},
		{name: "a claims path that is a string", file: fmt.Sprintf(entry, "family_name", "true"), fault: "family_name"},
		{name: "a claims path element that is a list", file: fmt.Sprintf(entry, "[[]]", "true"), fault: "element 0"},
		{name: "a value of another type", file: fmt.Sprintf(entry, "[given_name]", "notabool"), fault: "notabool"},
		{name: "a key a credential query repeats", file: "templates:\n  - id: t1\n    dcql:\n      credentials:\n        - id: other\n          id: q1\n", fault: "id is named more than once"},
		{name: "a list that is a scalar", file: "templates: notalist\n", fault: "$.templates"},
		{name: "entries that are scalars", file: top + "templates: [a, b]\n", id: "top", scopes: []string{"stop"}, fault: "$.templates[0]"},
		{name: "top-level keys beside the list", file: top + fmt.Sprintf(entry, "[given_name]", "notabool"), id: "top", scopes: []string{"stop"}, fault: "notabool"},
		{name: "an alias in the list", file: alias, fault: "non-empty array"},
		{name: "a default template of another type", file: "default_template: [x]\n" + top, id: "top", scopes: []string{"stop"}, fault: "!!seq"},
		{
			name:   "an alias and top-level claims beside the list",
			file:   "x-meta: &meta\n  vct_values: [urn:x]\n" + top + queryTop + "templates:\n  - id: t1\n    dcql:\n      credentials:\n        - id: q1\n          meta: *meta\n    enabled: notabool\n",
			id:     "top",
			scopes: []string{"stop"},
			query:  `{"credentials":[{"id":"q0","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"claims":[{"path":["place_of_birth","locality"]}]}]}`,
			fault:  "notabool",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "templates.yaml")
			require.NoError(t, os.WriteFile(file, []byte(tt.file), 0o600))
			config, err := LoadPresentationRequests(t.Context(), dir)
			require.NoError(t, err)

			require.Len(t, config.Templates, 1)
			template := config.Templates[0]
			assert.Equal(t, tt.id, template.ID)
			assert.Equal(t, tt.scopes, template.OIDCScopes)
			assert.True(t, template.IsEnabled())
			if tt.query == "" {
				assert.Nil(t, template.DCQLQuery)
			} else {
				query, err := json.Marshal(template.DCQLQuery)
				require.NoError(t, err)
				assert.JSONEq(t, tt.query, string(query))
			}

			require.Len(t, config.Fallbacks, 1)
			assert.Equal(t, file, config.Fallbacks[0].File)
			assert.ErrorContains(t, config.Fallbacks[0], tt.fault)
		})
	}
}

// An empty path decodes where the earlier release read a list of strings,
// so a service that reads no such field loads the file. A service that
// reads the field sees an unset path, which its check refuses. The loader
// warns of the path, and the converter leaves it as written.
func TestEmptyPathDecodes(t *testing.T) {
	const aux = "common:\n  credential_metadata:\n    nym_auth:\n      format: mso_mdoc\n      auxiliary_data:\n        %s:\n          - {type: hash_commitment, alg: sha-256, path: []}\n"
	const preset = "verifier:\n  presets:\n    P:\n      credentials:\n        pid:\n          %s:\n            - %s\n"
	scope := func(c *model.Cfg) *model.VerificationPresetScope { return c.Verifier.Presets["P"].Credentials["pid"] }
	tests := []struct {
		name, file string
		path       func(*model.Cfg) claimpath.Pointer
	}{
		{
			name: "a preset claim",
			file: fmt.Sprintf(preset, "claims", "path: []"),
			path: func(c *model.Cfg) claimpath.Pointer { return scope(c).Claims[0].Path },
		},
		{
			name: "a preset's excluded claim",
			file: fmt.Sprintf(preset, "exclude_claims", "path: []"),
			path: func(c *model.Cfg) claimpath.Pointer { return scope(c).ExcludeClaims[0].Path },
		},
		{
			name: "a preset's validation",
			file: fmt.Sprintf(preset, "validations", "{rule: age_over, path: [], value: 18}"),
			path: func(c *model.Cfg) claimpath.Pointer { return scope(c).Validations[0].Path },
		},
		{
			name: "a to_wallet entry",
			file: fmt.Sprintf(aux, "to_wallet"),
			path: func(c *model.Cfg) claimpath.Pointer {
				return c.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToWallet[0].Path
			},
		},
		{
			name: "a to_issuer entry",
			file: fmt.Sprintf(aux, "to_issuer"),
			path: func(c *model.Cfg) claimpath.Pointer {
				return c.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToIssuer[0].Path
			},
		},
		{
			name: "a credential attribute",
			file: "common:\n  credential_metadata:\n    pid:\n      format: dc+sd-jwt\n      attributes: {en-US: {Given name: []}}\n",
			path: func(c *model.Cfg) claimpath.Pointer {
				return c.Common.CredentialMetadata["pid"].Attributes["en-US"]["Given name"]
			},
		},
		{
			name: "a hash_commitment derivation",
			file: "apigw:\n  data_sources:\n    presentation:\n      scopes:\n        nym_auth:\n          from:\n            pid:\n              derivations:\n                - hash_commitment: {path: []}\n",
			path: func(c *model.Cfg) claimpath.Pointer {
				return c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"].Derivations[0].HashCommitment.Path
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(file, []byte(tt.file), 0o600))
			cfg, err := DecodeFile(t.Context(), file, nil)
			require.NoError(t, err)
			assert.True(t, tt.path(cfg).IsZero())
			require.Len(t, cfg.Deprecations, 1)
			assert.Equal(t, "[]", cfg.Deprecations[0].Old)
			assert.NotEmpty(t, cfg.Deprecations[0].Note)

			text, _, err := UpgradeFile(t.Context(), file, []byte(tt.file), nil)
			require.NoError(t, err)
			assert.Equal(t, tt.file, string(text))
		})
	}
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
