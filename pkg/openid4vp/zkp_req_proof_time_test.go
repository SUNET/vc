package openid4vp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The shared proof_time vectors: rendering, parsing and the tolerance
// window.
//
// T is the one value the prover and this verifier must agree on byte
// for byte - it is a public input to the circuit - so its spelling is
// not a local matter. The vectors' expected texts were computed with
// an independent implementation, which is what makes them worth
// running rather than a restatement of this code.
func TestProofTimeVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "proof_time", "proof_time.json"))
	require.NoError(t, err)

	var vectors struct {
		Render []struct {
			Secs int64  `json:"secs"`
			Text string `json:"text"`
		} `json:"render"`
		RenderErrors []struct {
			Secs  int64  `json:"secs"`
			Error string `json:"error"`
		} `json:"render_errors"`
		ParseOK []struct {
			Text string `json:"text"`
			Secs int64  `json:"secs"`
		} `json:"parse_ok"`
		ParseErrors []struct {
			Text  string `json:"text"`
			Error string `json:"error"`
		} `json:"parse_errors"`
		Tolerance []struct {
			Name       string `json:"name"`
			NowSecs    int64  `json:"now_secs"`
			SkewSecs   int64  `json:"skew_secs"`
			MaxAgeSecs int64  `json:"max_age_secs"`
			ProofTime  string `json:"proof_time"`
			Expect     string `json:"expect"`
		} `json:"tolerance"`
	}
	require.NoError(t, json.Unmarshal(raw, &vectors))
	require.NotEmpty(t, vectors.Render)
	require.NotEmpty(t, vectors.Tolerance)

	t.Run("render", func(t *testing.T) {
		for _, tc := range vectors.Render {
			got, err := RenderProofTime(tc.Secs)
			require.NoError(t, err, "%d", tc.Secs)
			assert.Equal(t, tc.Text, got, "%d", tc.Secs)
			assert.Len(t, got, ProofTimeBytes)
		}
	})

	t.Run("render errors", func(t *testing.T) {
		for _, tc := range vectors.RenderErrors {
			_, err := RenderProofTime(tc.Secs)
			require.Error(t, err, "%d", tc.Secs)
			assert.Equal(t, tc.Error, proofTimeCode(err), "%d", tc.Secs)
		}
	})

	t.Run("parse", func(t *testing.T) {
		for _, tc := range vectors.ParseOK {
			got, err := ParseProofTime(tc.Text)
			require.NoError(t, err, tc.Text)
			assert.Equal(t, tc.Secs, got.Unix(), tc.Text)
			// And round-trips, so the two directions agree.
			back, err := RenderProofTime(got.Unix())
			require.NoError(t, err)
			assert.Equal(t, tc.Text, back)
		}
	})

	t.Run("parse errors", func(t *testing.T) {
		for _, tc := range vectors.ParseErrors {
			_, err := ParseProofTime(tc.Text)
			require.Error(t, err, tc.Text)
			assert.Equal(t, tc.Error, proofTimeCode(err), "%q", tc.Text)
		}
	})

	t.Run("tolerance", func(t *testing.T) {
		for _, tc := range vectors.Tolerance {
			t.Run(tc.Name, func(t *testing.T) {
				now := time.Unix(tc.NowSecs, 0).UTC()
				skew := time.Duration(tc.SkewSecs) * time.Second
				maxAge := time.Duration(tc.MaxAgeSecs) * time.Second

				parsed, parseErr := ParseProofTime(tc.ProofTime)
				if parseErr != nil {
					// A tolerance case whose value is not even the
					// right form fails on the form, which is the
					// stricter statement.
					assert.Equal(t, tc.Expect, proofTimeCode(parseErr))
					return
				}
				err := CheckProofTimeTolerance(parsed, now, skew, maxAge)
				if tc.Expect == "ok" {
					assert.NoError(t, err)
					return
				}
				require.Error(t, err)
				assert.Equal(t, tc.Expect, proofTimeCode(err))
			})
		}
	})
}

// proofTimeCode names the sentinel an error carries, which is what the
// vectors assert.
func proofTimeCode(err error) string {
	for _, sentinel := range []error{
		ErrProofTimeForm, ErrProofTimeNotAnInstant, ErrProofTimeOutOfRange,
		ErrProofTimeInFuture, ErrProofTimeTooOld,
	} {
		if errors.Is(err, sentinel) {
			return sentinel.Error()
		}
	}
	return "unclassified: " + err.Error()
}

// The recommended tolerances are the shared ones, so a deployment
// that does not choose gets what every other implementation assumes.
func TestRecommendedTolerancesMatchTheSpecification(t *testing.T) {
	assert.Equal(t, 60*time.Second, RecommendedSkew)
	assert.Equal(t, 600*time.Second, RecommendedMaxAge)
}
