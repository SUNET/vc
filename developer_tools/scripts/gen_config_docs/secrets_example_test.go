package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yamlv2 "gopkg.in/yaml.v2"
)

// The documented secrets example must be loadable.
//
// It is a fill-in template, so an operator copies it. When IssuerSecrets
// lost its last field, the generator fell through to the scalar branch
// and emitted `issuer: "<value>"` - which cannot decode into a struct,
// so a copied secrets file failed to load and the service would not
// start. The generator is the only thing standing between an empty
// struct and that outcome, and nothing was checking it.
//
// Parsed STRICTLY, which is the point: a key with no field behind it is
// exactly the defect, and a lenient parse would accept the broken
// example as happily as the good one.
func TestGeneratedSecretsExampleLoads(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/CONFIGURATION.md")
	require.NoError(t, err, "the generated reference must exist; run `make gen-config-docs`")

	block := secretsExampleBlock(t, string(raw))

	var secrets model.Secrets
	require.NoError(t, yamlv2.UnmarshalStrict([]byte(block), &secrets),
		"an operator copying this example must get a secrets file that loads")

	// And it is not vacuously loadable by being empty.
	assert.Contains(t, block, "seeds:", "the seed sources are the section this guard was added for")
	assert.NotContains(t, block, `issuer: "`,
		"a struct section must never be emitted as a scalar")
}

// secretsExampleBlock returns the fenced YAML block that documents the
// secrets file.
func secretsExampleBlock(t *testing.T, doc string) string {
	t.Helper()
	blocks := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(doc, -1)
	for _, b := range blocks {
		// The secrets example is the one carrying the per-service
		// secret sections rather than main-configuration keys.
		if strings.Contains(b[1], "registry:") && strings.Contains(b[1], "verifier:") && strings.Contains(b[1], "seeds:") {
			return b[1]
		}
	}
	t.Fatal("no secrets example found in docs/CONFIGURATION.md; this guard is not looking at anything")
	return ""
}
