package oauth2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateCodeVerifier(t *testing.T) {
	tests := []struct {
		name         string
		wantedLength int
	}{
		{
			name:         "OK",
			wantedLength: 43,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateCodeVerifier()
			assert.NoError(t, err)
			fmt.Println("got: ", got)

			assert.GreaterOrEqual(t, len(got), 43)
		})
	}
}

func TestCreateCodeChallenge(t *testing.T) {
	tests := []struct {
		name                string
		codeChallengeMethod string
		codeVerifier        string
	}{
		{
			name:                "OK",
			codeChallengeMethod: CodeChallengeMethodS256,
			codeVerifier:        "test_code",
		},
		{
			name:                "OK",
			codeChallengeMethod: CodeChallengeMethodPlain,
			codeVerifier:        "test_code",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateCodeChallenge(tt.codeChallengeMethod, tt.codeVerifier)
			fmt.Println("got: ", got)
			assert.NotEmpty(t, got)
		})
	}
}

func TestValidatePKCE(t *testing.T) {
	tests := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod string
		wantErr             error
	}{
		{
			name:                "valid S256 PKCE",
			codeVerifier:        "test_code_verifier_123",
			codeChallenge:       CreateCodeChallenge(CodeChallengeMethodS256, "test_code_verifier_123"),
			codeChallengeMethod: CodeChallengeMethodS256,
			wantErr:             nil,
		},
		{
			name:                "valid plain PKCE",
			codeVerifier:        "test_code_verifier_456",
			codeChallenge:       "test_code_verifier_456",
			codeChallengeMethod: CodeChallengeMethodPlain,
			wantErr:             nil,
		},
		{
			name:                "no PKCE used",
			codeVerifier:        "",
			codeChallenge:       "",
			codeChallengeMethod: "",
			wantErr:             nil,
		},
		{
			name:                "missing code verifier",
			codeVerifier:        "",
			codeChallenge:       "some_challenge",
			codeChallengeMethod: CodeChallengeMethodS256,
			wantErr:             ErrInvalidRequest,
		},
		{
			name:                "invalid code verifier",
			codeVerifier:        "wrong_verifier",
			codeChallenge:       CreateCodeChallenge(CodeChallengeMethodS256, "correct_verifier"),
			codeChallengeMethod: CodeChallengeMethodS256,
			wantErr:             ErrInvalidGrant,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePKCE(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
