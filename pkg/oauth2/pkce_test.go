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

	// Test uniqueness - multiple calls should produce different verifiers
	t.Run("generates unique verifiers", func(t *testing.T) {
		verifier1, err := CreateCodeVerifier()
		assert.NoError(t, err)
		
		verifier2, err := CreateCodeVerifier()
		assert.NoError(t, err)
		
		assert.NotEqual(t, verifier1, verifier2, "consecutive verifiers should be unique")
	})

	// Test that generated verifier works with challenge creation
	t.Run("verifier works with challenge creation", func(t *testing.T) {
		verifier, err := CreateCodeVerifier()
		assert.NoError(t, err)
		
		challenge := CreateCodeChallenge(CodeChallengeMethodS256, verifier)
		assert.NotEmpty(t, challenge)
		assert.NotEqual(t, verifier, challenge, "S256 challenge should differ from verifier")
		
		// Verify the challenge can be validated
		err = ValidatePKCE(verifier, challenge, CodeChallengeMethodS256)
		assert.NoError(t, err)
	})
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

	// Test S256 produces deterministic output
	t.Run("S256 is deterministic", func(t *testing.T) {
		verifier := "test_verifier_123"
		challenge1 := CreateCodeChallenge(CodeChallengeMethodS256, verifier)
		challenge2 := CreateCodeChallenge(CodeChallengeMethodS256, verifier)
		assert.Equal(t, challenge1, challenge2, "same verifier should produce same S256 challenge")
	})

	// Test plain method returns verifier as-is
	t.Run("plain returns verifier unchanged", func(t *testing.T) {
		verifier := "my_plain_verifier"
		challenge := CreateCodeChallenge(CodeChallengeMethodPlain, verifier)
		assert.Equal(t, verifier, challenge, "plain method should return verifier unchanged")
	})

	// Test empty challenge method defaults to plain
	t.Run("empty method behaves as plain", func(t *testing.T) {
		verifier := "test_verifier"
		challenge := CreateCodeChallenge("", verifier)
		assert.Equal(t, verifier, challenge, "empty method should behave like plain")
	})
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
