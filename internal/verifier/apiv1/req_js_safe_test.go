package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The server half of this is lossless on purpose - decodeExact uses
// json.Decoder.UseNumber so a configured value survives verbatim - and
// the loss happens entirely in the browser, which is why it has to be
// checked rather than assumed.
func TestReqParamsMustSurviveTheBrowsersNumbers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		ok    bool
	}{
		{"a small integer", 7, true},
		{"the largest exact integer", int64(9007199254740992), true},
		{"one past it", int64(9007199254740993), false},
		{"a large round number, which is exact as a float64", int64(1) << 62, true},
		{"a decimal with more precision than a float64 holds", json.Number("1.00000000000000001"), false},
		{"an ordinary decimal", 1.5, true},
		{"a string, which has no such problem", "9007199254740993", true},
		{"nested inside an object", map[string]any{"inner": int64(9007199254740993)}, false},
		{"nested inside an array", []any{1, int64(9007199254740993)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := reqSurvivesTheBrowser([]openid4vp.ReqItem{{
				ID: openid4vp.FunctionPseudonym, Return: "h",
				Params: map[string]any{"p": tc.value},
			}})
			if tc.ok {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "JavaScript number")
		})
	}
}

// And the refusal has to reach the publishing path, not just exist.
func TestCircuitZkPresetWithAnUnsafeParamIsOmitted(t *testing.T) {
	cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{
		Format: openid4vp.FormatCircuitZk,
		Req: []openid4vp.ReqItem{{
			ID: openid4vp.FunctionPseudonym, Return: "nym-123",
			Params: map[string]any{
				"config":  "known-offender-matching-ssc",
				"counter": int64(9007199254740993),
			},
		}},
	}, nil)
	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(t.Context())
	require.NoError(t, err)
	if preset := reply.Presets["Nym"]; preset != nil {
		assert.Empty(t, preset.Credentials,
			"a preset whose proof input the browser would silently change must not be published")
	}
}
