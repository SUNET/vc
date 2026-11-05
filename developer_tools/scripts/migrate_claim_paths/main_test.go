package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/legacyclaims"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyDir holds the earlier release's version of each in-repo
// configuration and presentation request file.
const legacyDir = "../../../pkg/configuration/testdata/legacy"

// The converter rewrites the earlier release's files into files that load
// as the same configuration or templates, with every comment kept, and a
// second run changes nothing. A claim_mappings the converter rewrites maps
// the same claims as the earlier map.
func TestMigrateKeepsTheMeaningAndTheComments(t *testing.T) {
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	dir := t.TempDir()
	var files []string
	require.NoError(t, filepath.WalkDir(legacyDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(legacyDir, path)
		if err != nil {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		files = append(files, target)
		return os.WriteFile(target, src, 0o600)
	}))
	require.NotEmpty(t, files)

	args := append([]string{"-schemas", "/metadata=" + filepath.Join(root, "metadata")}, files...)
	var report bytes.Buffer
	require.NoError(t, run(t.Context(), args, &report))
	converted := readFiles(t, files)
	require.NoError(t, run(t.Context(), args, &report))
	assert.Equal(t, converted, readFiles(t, files), "a second run changes nothing")

	schemas := func(path string) string {
		if rest, ok := strings.CutPrefix(path, "/metadata/"); ok {
			return filepath.Join(root, "metadata", rest)
		}
		return path
	}
	for _, file := range files {
		rel, err := filepath.Rel(dir, file)
		require.NoError(t, err)
		t.Run(rel, func(t *testing.T) {
			legacy := filepath.Join(legacyDir, rel)
			original, err := os.ReadFile(legacy)
			require.NoError(t, err)
			assert.Equal(t, comments(original), comments(converted[file]), "comments")

			doc, err := legacyclaims.Parse(legacy, original)
			require.NoError(t, err)
			if !legacyclaims.IsTemplateFile(doc) {
				want, err := configuration.LoadFile(t.Context(), legacy, schemas)
				require.NoError(t, err)
				got, err := configuration.LoadFile(t.Context(), file, schemas)
				require.NoError(t, err)
				assert.Empty(t, got.Deprecations, "the converted file holds no earlier spelling")
				want.Deprecations = nil
				assert.Equal(t, want, got)
				return
			}
			want, wantErr := loadTemplates(t, original)
			got, gotErr := loadTemplates(t, converted[file])
			if wantErr != nil {
				require.Error(t, gotErr)
				assert.Equal(t, wantErr.Error(), gotErr.Error())
				return
			}
			require.NoError(t, gotErr)
			for _, rewrite := range got.Deprecations {
				assert.NotEmpty(t, rewrite.Note, "the converter leaves only claim_mappings it reports: %s", rewrite)
			}
			require.Len(t, got.Templates, len(want.Templates))
			for i := range want.Templates {
				assertSameMappings(t, want.Templates[i], got.Templates[i])
				want.Templates[i].ClaimMappings, got.Templates[i].ClaimMappings = openid4vp.ClaimMappings{}, openid4vp.ClaimMappings{}
			}
			assert.Equal(t, want.Templates, got.Templates)
		})
	}
}

// The converter rewrites a file with a YAML alias in place when the
// rewrite reads as the file does. It leaves the file as written, and names
// it, when an alias reads a spelling the rewrite would give another
// meaning: a claim read again as a URL, or an anchor the keyed
// claim_mappings drops.
func TestMigrateRewritesAFileWithAliasesWhenItKeepsItsMeaning(t *testing.T) {
	const mapping = "apigw:\n  auth_providers:\n    oidc:\n      attribute_mapping:\n        birthdate:\n          claim: %s\n"
	const template = "templates:\n  - id: age\n    oidc_scopes: [age]\n    dcql:\n      credentials:\n        - id: age\n          format: dc+sd-jwt\n%s          claims:\n            - path: [age_over_18]\n    claim_mappings:\n%s"
	const meta = "x-meta: &meta\n  vct_values: [urn:credential:age:1]\n"
	const mdoc = "templates:\n  - id: mdl\n    oidc_scopes: [mdl]\n    dcql:\n      credentials:\n        - <<: {format: mso_mdoc}\n          id: mdl\n          meta:\n            doctype_value: org.iso.18013.5.1.mDL\n          claims:\n            - path: [org.iso.18013.5.1, family_name]\n    claim_mappings:\n%s"
	tests := []struct {
		name, file string
		// want is the file once converted, and empty when the converter
		// leaves it as written.
		want string
	}{
		{
			name: "a configuration with an alias outside the claims",
			file: "x-url: &url https://issuer.example\n" + fmt.Sprintf(mapping, "birthdate") + "  public_url: *url\n",
			want: "x-url: &url https://issuer.example\n" + fmt.Sprintf(mapping, "[birthdate]") + "  public_url: *url\n",
		},
		{
			name: "a configuration whose alias reads a claim as a URL",
			file: fmt.Sprintf(mapping, "&name birthdate") + "  public_url: *name\n",
		},
		{
			name: "a template with an alias outside the claims",
			file: meta + fmt.Sprintf(template, "          meta: *meta\n", "      age_over_18: age_over_18\n"),
			want: meta + fmt.Sprintf(template, "          meta: *meta\n", "      age:\n        - {path: [age_over_18], claim: age_over_18}\n"),
		},
		{
			name: "a template whose alias reads a claim the keyed form drops",
			file: fmt.Sprintf(template, "", "      age_over_18: &claim age_over_18\n    description: *claim\n"),
		},
		{
			name: "a template whose credential query takes its format from a merge key",
			file: fmt.Sprintf(mdoc, "      family_name: family_name\n"),
			want: fmt.Sprintf(mdoc, "      mdl:\n        - {path: [org.iso.18013.5.1, family_name], claim: family_name}\n"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))
			var report bytes.Buffer
			require.NoError(t, run(t.Context(), []string{path}, &report))
			got, err := os.ReadFile(path)
			require.NoError(t, err)
			want := tt.want
			if want == "" {
				want = tt.file
				assert.Contains(t, report.String(), path, "the report names the file left as written")
			}
			assert.Equal(t, want, string(got))
		})
	}
}

// readFiles returns the content of each file.
func readFiles(t *testing.T, files []string) map[string][]byte {
	t.Helper()
	contents := make(map[string][]byte, len(files))
	for _, file := range files {
		src, err := os.ReadFile(file)
		require.NoError(t, err)
		contents[file] = src
	}
	return contents
}

// comments counts the comments of a YAML text.
func comments(src []byte) int {
	n := 0
	for _, tk := range lexer.Tokenize(string(src)) {
		if tk.Type == token.CommentType {
			n++
		}
	}
	return n
}

// loadTemplates loads a presentation request file as the verifier loads
// its directory of them. An error names the directory DIR.
func loadTemplates(t *testing.T, src []byte) (*configuration.PresentationRequestConfig, error) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "templates.yaml"), src, 0o600))
	config, err := configuration.LoadPresentationRequests(t.Context(), dir)
	if err != nil {
		return nil, errors.New(strings.ReplaceAll(err.Error(), dir, "DIR"))
	}
	return config, nil
}

// assertSameMappings maps one presentation per credential query of the
// template, with a value at each claim the earlier map names, through
// both templates' claim mappings. A presented mdoc carries each element
// of org.iso.18013.5.1 under its bare identifier too, as the claims
// extractor does.
func assertSameMappings(t *testing.T, legacy, converted *configuration.PresentationRequestTemplate) {
	t.Helper()
	names, ok := legacy.ClaimMappings.ByName()
	require.True(t, ok, "the earlier release wrote claim_mappings as a map from dotted names")
	want, err := legacy.GetClaimMappings()
	require.NoError(t, err)
	got, err := converted.GetClaimMappings()
	require.NoError(t, err)

	var presentations []openid4vp.Presentation
	for _, query := range legacy.DCQLQuery.Credentials {
		claims := map[string]any{"unmapped": "a claim no entry names"}
		for name := range names {
			value := "the value of " + name
			if openid4vp.IsMdocFormat(query.Format) || openid4vp.IsMdocZkFormat(query.Format) {
				claims[name] = value
				claims["org.iso.18013.5.1."+name] = value
				continue
			}
			setNested(claims, strings.Split(name, "."), value)
		}
		presentations = append(presentations, openid4vp.Presentation{QueryID: query.ID, Shape: openid4vp.PresentedShape(query.Format), Claims: claims})
	}
	wantClaims, err := want.MapClaims(presentations)
	require.NoError(t, err)
	gotClaims, err := got.MapClaims(presentations)
	require.NoError(t, err)
	assert.Equal(t, wantClaims, gotClaims, "claim_mappings")
}

// setNested writes value at keys, creating the objects on the way.
func setNested(claims map[string]any, keys []string, value any) {
	for _, key := range keys[:len(keys)-1] {
		next, ok := claims[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			claims[key] = next
		}
		claims = next
	}
	claims[keys[len(keys)-1]] = value
}
