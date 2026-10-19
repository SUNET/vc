package apiv1

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

// The documented example must be configuration this build accepts.
//
// It is written for an operator to copy, so a key that has been renamed
// or a field that never existed turns the document into a deployment
// that refuses to start - and the person copying it has every reason to
// trust it. Parsed STRICTLY, which is the point: a key with no field
// behind it is exactly the failure worth catching.
func TestWorkedExampleConfigLoads(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/issuer/SEED_COMMITMENTS.md")
	require.NoError(t, err)
	doc := string(raw)

	blocks := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(doc, -1)
	require.NotEmpty(t, blocks)

	checked := 0
	for _, b := range blocks {
		block := b[1]
		if !strings.Contains(block, "seeds:") && !strings.Contains(block, "commitments:") {
			continue
		}
		// Comment-only placeholder lines ("# seed_bytes: 16") stay
		// commented, so what is parsed is what an operator would get by
		// copying the block verbatim.
		//
		// A block carrying `secret:` is a SECRETS FILE example, not the
		// main configuration: SeedSource.Secret is yaml:"-" on purpose,
		// because the derivation secret must not be writable in
		// config.yaml. Parsing it as the main config would be this
		// test misreading the document rather than the document being
		// wrong.
		target := any(&model.Cfg{})
		if strings.Contains(block, "secret:") && !strings.Contains(block, "model:") {
			target = &model.Secrets{}
		}
		require.NoErrorf(t, yamlv2.UnmarshalStrict([]byte(block), target),
			"a configuration block in SEED_COMMITMENTS.md does not load:\n%s", block)
		checked++
	}
	assert.GreaterOrEqual(t, checked, 2,
		"the seed source and the commitment blocks must both be checked, or this guard is not looking at anything")
}

// And the example really does turn delivery on, so the document cannot
// drift into describing the commitment-only setup while claiming to
// describe delivery.
func TestWorkedExampleTurnsDeliveryOn(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/issuer/SEED_COMMITMENTS.md")
	require.NoError(t, err)

	var withDelivery *model.CommitmentClaim
	for _, b := range regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(string(raw), -1) {
		var cfg model.Cfg
		if yamlv2.UnmarshalStrict([]byte(b[1]), &cfg) != nil || cfg.Common == nil {
			continue
		}
		for _, meta := range cfg.Common.CredentialMetadata {
			for _, claim := range meta.Commitments {
				if claim != nil && claim.Deliver {
					withDelivery = claim
				}
			}
		}
	}
	require.NotNil(t, withDelivery, "the worked example must show deliver: true")
	assert.NotEmpty(t, withDelivery.Subjects, "and the ordered subject identifiers it derives from")
	assert.Empty(t, withDelivery.Namespace,
		"the example relies on the default namespace; if it names one, say which in the prose too")
}
