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
//
// Every expectation below was taken from node, not from reasoning about
// IEEE 754: JSON.stringify(JSON.parse(x)) was run on each literal and the
// result compared to the input as an exact decimal. Two of them came out
// against what I had assumed, which is the reason for doing it that way.
func TestReqParamsMustSurviveTheBrowsersNumbers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		ok    bool
	}{
		{"a small integer", 7, true},
		{"a negative one", -7, true},
		{"an ordinary decimal", 1.5, true},

		// Not exactly representable as a float64, and survives anyway:
		// ECMAScript prints the shortest decimal that parses back to the
		// same double, so this comes out "0.1". Testing representability
		// instead of round-tripping refused presets that were fine.
		{"a decimal that is not exactly representable", json.Number("0.1"), true},
		{"the classic 0.1+0.2 result", json.Number("0.30000000000000004"), true},

		{"the largest exact integer", int64(9007199254740992), true},
		{"one past it", int64(9007199254740993), false},
		{"two past it, which lands on a representable value", int64(9007199254740994), true},

		// And the other direction, which I had assumed was safe and is
		// not: 2^62 IS exactly representable, and the shortest decimal
		// that round-trips to it is 4611686018427388000 - so that is what
		// the picker posts back, and a wallet reading it as an integer
		// gets a different number than the one configured.
		{"2^62: exactly representable, and still changed", int64(1) << 62, false},
		{"the value it is changed INTO, which is stable", int64(4611686018427388000), true},

		{"a decimal with more precision than a float64 holds", json.Number("1.00000000000000001"), false},
		{"an integer too long to survive", json.Number("123456789012345678901234567890"), false},

		// Out of range entirely. JSON.stringify turns an Infinity into
		// null, so the parameter does not change - it disappears.
		{"beyond float64 range", json.Number("1e400"), false},
		{"and below it, which underflows to zero", json.Number("1e-400"), false},

		{"a string, which has no such problem", "9007199254740993", true},
		{"nested inside an object", map[string]any{"inner": int64(9007199254740993)}, false},
		{"nested inside an array", []any{1, int64(9007199254740993)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := reqSurvivesTheBrowser([]openid4vp.ReqItem{{
				FnID: openid4vp.FunctionPseudonym, Return: "h",
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
		Format: openid4vp.FormatZkpReq,
		Req: []openid4vp.ReqItem{{
			FnID: openid4vp.FunctionPseudonym, Return: "nym-123",
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
