package oauth2

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractClientIDFromAssertion(t *testing.T) {
	// Helper to build a JWT with a given payload
	makeJWT := func(payload string) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
		p := base64.RawURLEncoding.EncodeToString([]byte(payload))
		return header + "." + p + ".fakesig"
	}

	tests := []struct {
		name      string
		assertion string
		wantSub   string
		wantErr   string
	}{
		{
			name:      "valid sub claim",
			assertion: makeJWT(`{"sub":"my-client-id","iss":"my-client-id"}`),
			wantSub:   "my-client-id",
		},
		{
			name:      "missing sub claim",
			assertion: makeJWT(`{"iss":"my-client-id"}`),
			wantErr:   "missing 'sub' claim",
		},
		{
			name:      "empty sub claim",
			assertion: makeJWT(`{"sub":""}`),
			wantErr:   "missing 'sub' claim",
		},
		{
			name:      "invalid JWT format — too few parts",
			assertion: "only.two",
			wantErr:   "invalid JWT format",
		},
		{
			name:      "invalid JWT format — too many parts",
			assertion: "a.b.c.d",
			wantErr:   "invalid JWT format",
		},
		{
			name:      "invalid base64 payload",
			assertion: "header.!!!invalid!!!.sig",
			wantErr:   "failed to decode JWT payload",
		},
		{
			name:      "invalid JSON payload",
			assertion: "header." + base64.RawURLEncoding.EncodeToString([]byte(`not json`)) + ".sig",
			wantErr:   "failed to parse JWT claims",
		},
		{
			name:      "sub exceeds max length",
			assertion: makeJWT(`{"sub":"` + strings.Repeat("a", 129) + `"}`),
			wantErr:   "exceeds maximum length",
		},
		{
			name:      "sub contains non-printable character",
			assertion: makeJWT(`{"sub":"client\u0001id"}`),
			wantErr:   "non-printable character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, err := ExtractClientIDFromAssertion(tt.assertion)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Empty(t, sub)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantSub, sub)
			}
		})
	}
}
