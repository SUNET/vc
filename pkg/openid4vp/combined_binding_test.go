package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCombinedBindingVerifier_SingleCredential(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			KeyBinding:  KeyBindingConfig{Enabled: true},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", HolderKeyThumbprint: "abc123", Claims: map[string]any{"sub": "user1"}},
	})

	assert.NoError(t, err)
	assert.Nil(t, result, "single credential should not trigger binding verification")
}

func TestCombinedBindingVerifier_EmptyCredentials(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			KeyBinding:  KeyBindingConfig{Enabled: true},
		},
	}

	result, err := v.Verify(nil)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCombinedBindingVerifier_KeyBinding_SameKey(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			KeyBinding:  KeyBindingConfig{Enabled: true},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", HolderKeyThumbprint: "thumbprint-abc", Claims: map[string]any{"sub": "user1"}},
		{Scope: "diploma", HolderKeyThumbprint: "thumbprint-abc", Claims: map[string]any{"sub": "user1"}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Bound)
	assert.True(t, result.Valid())
	assert.NoError(t, result.Err())
	assert.Equal(t, BindingConfidenceHigh, result.HighestConfidence)

	// Should have session-based + key-based results
	assert.Len(t, result.Results, 2)
	assert.Equal(t, BindingMethodSession, result.Results[0].Method)
	assert.Equal(t, BindingMethodKey, result.Results[1].Method)
	assert.Equal(t, BindingConfidenceHigh, result.Results[1].Confidence)
}

func TestCombinedBindingVerifier_KeyBinding_DifferentKeys(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			KeyBinding:  KeyBindingConfig{Enabled: true},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", HolderKeyThumbprint: "thumbprint-abc", Claims: map[string]any{}},
		{Scope: "diploma", HolderKeyThumbprint: "thumbprint-def", Claims: map[string]any{}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Bound)
	assert.False(t, result.Valid())
	assert.Error(t, result.Err())
	assert.Equal(t, BindingConfidenceLow, result.HighestConfidence)
	assert.Contains(t, result.Results[1].Error, "holder key mismatch")
	assert.Contains(t, result.Err().Error(), "holder key mismatch")
}

func TestCombinedBindingVerifier_KeyBinding_DifferentKeys_WarnMode(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementWarn,
			KeyBinding:  KeyBindingConfig{Enabled: true},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", HolderKeyThumbprint: "thumbprint-abc", Claims: map[string]any{}},
		{Scope: "diploma", HolderKeyThumbprint: "thumbprint-def", Claims: map[string]any{}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	// In warn mode, binding is still considered true (not enforced)
	assert.True(t, result.Bound)
	assert.False(t, result.Valid()) // Bound but has errors → not valid
	assert.Error(t, result.Err())
	assert.Contains(t, result.Results[1].Error, "holder key mismatch")
}

func TestCombinedBindingVerifier_AttributeBinding_Match(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			BindingAttributes: []BindingAttributeConfig{
				{Paths: []string{"sub"}},
			},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", Claims: map[string]any{"sub": "user123"}},
		{Scope: "diploma", Claims: map[string]any{"sub": "user123"}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Bound)
	assert.True(t, result.Valid())
	assert.NoError(t, result.Err())
	assert.Equal(t, BindingConfidenceMedium, result.HighestConfidence)
}

func TestCombinedBindingVerifier_AttributeBinding_Mismatch(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			BindingAttributes: []BindingAttributeConfig{
				{Paths: []string{"sub"}},
			},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", Claims: map[string]any{"sub": "user123"}},
		{Scope: "diploma", Claims: map[string]any{"sub": "user456"}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Bound)
	assert.False(t, result.Valid())
	assert.Error(t, result.Err())
	assert.Contains(t, result.Err().Error(), "attribute binding failed")
}

func TestCombinedBindingVerifier_CompoundAttributeBinding(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			BindingAttributes: []BindingAttributeConfig{
				{Paths: []string{"given_name", "family_name", "birth_date"}},
			},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", Claims: map[string]any{
			"given_name":  "Alice",
			"family_name": "Smith",
			"birth_date":  "1990-01-15",
		}},
		{Scope: "diploma", Claims: map[string]any{
			"given_name":  "Alice",
			"family_name": "Smith",
			"birth_date":  "1990-01-15",
		}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Bound)
	assert.Equal(t, BindingConfidenceMedium, result.HighestConfidence)
}

func TestCombinedBindingVerifier_CompoundAttributeBinding_PartialMismatch(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			BindingAttributes: []BindingAttributeConfig{
				{Paths: []string{"given_name", "family_name", "birth_date"}},
			},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", Claims: map[string]any{
			"given_name":  "Alice",
			"family_name": "Smith",
			"birth_date":  "1990-01-15",
		}},
		{Scope: "diploma", Claims: map[string]any{
			"given_name":  "Alice",
			"family_name": "Jones", // Different!
			"birth_date":  "1990-01-15",
		}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Bound)
}

func TestCombinedBindingVerifier_NestedAttributePath(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			BindingAttributes: []BindingAttributeConfig{
				{Paths: []string{"address.country"}},
			},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", Claims: map[string]any{
			"address": map[string]any{"country": "SE"},
		}},
		{Scope: "diploma", Claims: map[string]any{
			"address": map[string]any{"country": "SE"},
		}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Bound)
	assert.Equal(t, BindingConfidenceMedium, result.HighestConfidence)
}

func TestCombinedBindingVerifier_KeyAndAttributeBinding(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			KeyBinding:  KeyBindingConfig{Enabled: true},
			BindingAttributes: []BindingAttributeConfig{
				{Paths: []string{"sub"}},
			},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", HolderKeyThumbprint: "tp-same", Claims: map[string]any{"sub": "user1"}},
		{Scope: "diploma", HolderKeyThumbprint: "tp-same", Claims: map[string]any{"sub": "user1"}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Bound)
	assert.Equal(t, BindingConfidenceHigh, result.HighestConfidence)
	assert.Len(t, result.Results, 3) // session + key + attribute
}

func TestCombinedBindingVerifier_InsufficientKeyMaterial(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			KeyBinding:  KeyBindingConfig{Enabled: true},
			BindingAttributes: []BindingAttributeConfig{
				{Paths: []string{"sub"}},
			},
		},
	}

	// One credential has key, another doesn't
	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", HolderKeyThumbprint: "tp-abc", Claims: map[string]any{"sub": "user1"}},
		{Scope: "diploma", HolderKeyThumbprint: "", Claims: map[string]any{"sub": "user1"}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	// Attribute binding still succeeds, so bound = true
	assert.True(t, result.Bound)
	assert.Equal(t, BindingConfidenceMedium, result.HighestConfidence)
	// Key binding result should note insufficient material
	assert.Contains(t, result.Results[1].Details, "insufficient key material")
}

func TestCombinedBindingVerifier_ThreeCredentials_SameKey(t *testing.T) {
	v := &CombinedBindingVerifier{
		Config: CombinedPresentationConfig{
			Enabled:     true,
			Enforcement: BindingEnforcementEnforce,
			KeyBinding:  KeyBindingConfig{Enabled: true},
		},
	}

	result, err := v.Verify([]VerifiedCredentialBinding{
		{Scope: "pid", HolderKeyThumbprint: "tp-same", Claims: map[string]any{}},
		{Scope: "diploma", HolderKeyThumbprint: "tp-same", Claims: map[string]any{}},
		{Scope: "ehic", HolderKeyThumbprint: "tp-same", Claims: map[string]any{}},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Bound)
	assert.Equal(t, BindingConfidenceHigh, result.HighestConfidence)
}

func TestExtractHolderKeyThumbprint(t *testing.T) {
	t.Run("valid EC P-256 cnf", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Compute expected thumbprint via our helper
		expectedTP, err := ECPublicKeyToJWKThumbprint(&key.PublicKey)
		require.NoError(t, err)

		// Build claims with cnf.jwk
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		xBytes := key.PublicKey.X.FillBytes(make([]byte, byteLen))
		yBytes := key.PublicKey.Y.FillBytes(make([]byte, byteLen))

		claims := map[string]any{
			"cnf": map[string]any{
				"jwk": map[string]any{
					"kty": "EC",
					"crv": "P-256",
					"x":   encodeBase64URL(xBytes),
					"y":   encodeBase64URL(yBytes),
				},
			},
		}

		tp, err := ExtractHolderKeyThumbprint(claims)
		assert.NoError(t, err)
		assert.Equal(t, expectedTP, tp)
	})

	t.Run("missing cnf", func(t *testing.T) {
		claims := map[string]any{"iss": "https://example.com"}
		tp, err := ExtractHolderKeyThumbprint(claims)
		assert.NoError(t, err)
		assert.Empty(t, tp)
	})

	t.Run("cnf without jwk", func(t *testing.T) {
		claims := map[string]any{"cnf": map[string]any{"kid": "some-kid"}}
		tp, err := ExtractHolderKeyThumbprint(claims)
		assert.NoError(t, err)
		assert.Empty(t, tp)
	})
}

func TestComputeJWKThumbprint(t *testing.T) {
	t.Run("EC P-256", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
			"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		}

		tp, err := ComputeJWKThumbprint(jwk)
		assert.NoError(t, err)
		assert.NotEmpty(t, tp)
	})

	t.Run("missing kty", func(t *testing.T) {
		jwk := map[string]any{"crv": "P-256", "x": "abc", "y": "def"}
		_, err := ComputeJWKThumbprint(jwk)
		assert.Error(t, err)
	})

	t.Run("EC missing fields", func(t *testing.T) {
		jwk := map[string]any{"kty": "EC", "crv": "P-256"}
		_, err := ComputeJWKThumbprint(jwk)
		assert.Error(t, err)
	})

	t.Run("deterministic", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
			"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		}
		tp1, _ := ComputeJWKThumbprint(jwk)
		tp2, _ := ComputeJWKThumbprint(jwk)
		assert.Equal(t, tp1, tp2)
	})
}

func TestECPublicKeyToJWKThumbprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tp, err := ECPublicKeyToJWKThumbprint(&key.PublicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, tp)

	// Should be deterministic
	tp2, err := ECPublicKeyToJWKThumbprint(&key.PublicKey)
	assert.NoError(t, err)
	assert.Equal(t, tp, tp2)
}

func TestECPublicKeyToJWKThumbprint_CrossFormat(t *testing.T) {
	// Verify that computing thumbprint from *ecdsa.PublicKey matches
	// computing from the equivalent JWK map (cross-format binding)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// From public key directly
	tpFromKey, err := ECPublicKeyToJWKThumbprint(&key.PublicKey)
	require.NoError(t, err)

	// From JWK map
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	xBytes := key.PublicKey.X.FillBytes(make([]byte, byteLen))
	yBytes := key.PublicKey.Y.FillBytes(make([]byte, byteLen))
	jwkMap := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   encodeBase64URL(xBytes),
		"y":   encodeBase64URL(yBytes),
	}
	tpFromJWK, err := ComputeJWKThumbprint(jwkMap)
	require.NoError(t, err)

	assert.Equal(t, tpFromKey, tpFromJWK, "thumbprint from key and JWK map should match")
}

func TestResolveSimplePath(t *testing.T) {
	claims := map[string]any{
		"sub":         "user123",
		"given_name":  "Alice",
		"family_name": "Smith",
		"address": map[string]any{
			"country":  "SE",
			"locality": "Stockholm",
		},
	}

	assert.Equal(t, "user123", resolveSimplePath(claims, "sub"))
	assert.Equal(t, "Alice", resolveSimplePath(claims, "given_name"))
	assert.Equal(t, "SE", resolveSimplePath(claims, "address.country"))
	assert.Nil(t, resolveSimplePath(claims, "nonexistent"))
	assert.Nil(t, resolveSimplePath(claims, "address.nonexistent"))
}

func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
