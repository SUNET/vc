package helpers

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidationIdentity(t *testing.T) {
	tts := []struct {
		name string
		have *model.Identity
		want error
	}{
		{
			name: "empty",
			have: &model.Identity{},
			want: &Error{
				Title: "validation_error",
				Err: []map[string]any{
					{
						"field":           "authentic_source_person_id",
						"namespace":       "authentic_source_person_id",
						"type":            "string",
						"validation":      "required",
						"validationParam": "",
					},
					{
						"field":           "family_name",
						"namespace":       "family_name",
						"type":            "string",
						"validation":      "required",
						"validationParam": "",
					},
					{
						"field":           "given_name",
						"namespace":       "given_name",
						"type":            "string",
						"validation":      "required",
						"validationParam": "",
					},
					{
						"field":           "birth_date",
						"namespace":       "birth_date",
						"type":            "string",
						"validation":      "required",
						"validationParam": "",
					},
				},
			},
		},
		{
			name: "ok",
			have: &model.Identity{
				AuthenticSourcePersonID: "person-123",
				FamilyName:              "Doe",
				GivenName:               "John",
				BirthDate:               "1970-01-01",
			},
			want: nil,
		},
		{
			name: "wrong datetime format",
			have: &model.Identity{
				AuthenticSourcePersonID: "person-123",
				FamilyName:              "Doe",
				GivenName:               "John",
				BirthDate:               "1972-10-27 10:15:31.432635902 +0000 UTC",
			},
			want: &Error{
				Title: "validation_error",
				Err: []map[string]any{
					{
						"field":           "birth_date",
						"namespace":       "birth_date",
						"type":            "string",
						"validation":      "datetime",
						"validationParam": "2006-01-02",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSimple(tt.have)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStruct(t *testing.T) {
	type Name struct {
		First string `validate:"required"`
		Last  string `validate:"required"`
	}
	type myStruct struct {
		Names []Name `validate:"dive"`
	}

	tts := []struct {
		name string
		have myStruct
		want error
	}{
		{
			name: "empty",
			have: myStruct{
				Names: []Name{
					{
						First: "John",
					},
				},
			},
			want: &Error{
				Title: "validation_error",
				Err: []map[string]any{
					{
						"field":           "Last",
						"namespace":       "Names[0].Last",
						"type":            "string",
						"validation":      "required",
						"validationParam": "",
					},
				},
			},
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSimple(tt.have)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidationArrayOfIdentity(t *testing.T) {
	type myStruct struct {
		ID []model.Identity `validate:"dive"`
	}
	tts := []struct {
		name string
		Have myStruct
		want error
	}{
		{
			name: "Correct datetime format",
			Have: myStruct{
				ID: []model.Identity{
					{
						AuthenticSourcePersonID: "person-123",
						FamilyName:              "Doe",
						GivenName:               "John",
						BirthDate:               "1972-10-27",
					},
				},
			},
			want: nil,
		},
		{
			name: "wrong datetime format",
			Have: myStruct{
				ID: []model.Identity{
					{
						AuthenticSourcePersonID: "person-123",
						FamilyName:              "Doe",
						GivenName:               "John",
						BirthDate:               "1972-10-27 10:15:31.432635902 +0000 UTC",
					},
				},
			},
			want: &Error{
				Title: "validation_error",
				Err: []map[string]any{
					{
						"field":           "birth_date",
						"namespace":       "ID[0].birth_date",
						"type":            "string",
						"validation":      "datetime",
						"validationParam": "2006-01-02",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSimple(tt.Have)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHTTPURLValidator(t *testing.T) {
	validate, err := NewValidator()
	assert.NoError(t, err)

	tests := []struct {
		name        string
		url         string
		shouldError bool
	}{
		{
			name:        "Valid HTTPS URL",
			url:         "https://verifier.example.com",
			shouldError: false,
		},
		{
			name:        "Valid HTTP URL",
			url:         "http://localhost:8080",
			shouldError: false,
		},
		{
			name:        "Valid HTTPS URL with port",
			url:         "https://vc-interop-3.sunet.se:444",
			shouldError: false,
		},
		{
			name:        "Valid HTTPS URL with path",
			url:         "https://example.com/path/to/resource",
			shouldError: false,
		},
		{
			name:        "Invalid - missing scheme",
			url:         "verifier.example.com",
			shouldError: true,
		},
		{
			name:        "Invalid - host:port without scheme",
			url:         "vc-interop-3.sunet.se:444",
			shouldError: true,
		},
		{
			name:        "Invalid - just hostname",
			url:         "localhost",
			shouldError: true,
		},
		{
			name:        "Invalid - empty string",
			url:         "",
			shouldError: true,
		},
		{
			name:        "Invalid - wrong scheme (ftp)",
			url:         "ftp://example.com",
			shouldError: true,
		},
		{
			name:        "Invalid - scheme only",
			url:         "https://",
			shouldError: true,
		},
		{
			name:        "Invalid - scheme without host",
			url:         "http://",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.Var(tt.url, "httpurl")
			if tt.shouldError {
				assert.Error(t, err, "Expected validation error for URL: %s", tt.url)
			} else {
				assert.NoError(t, err, "Expected no validation error for URL: %s", tt.url)
			}
		})
	}
}

func TestAuthScopesSelfReference(t *testing.T) {
	validate, err := NewValidator()
	assert.NoError(t, err)

	tests := []struct {
		name          string
		ds            model.DataSources
		shouldError   bool
		errorContains string
	}{
		{
			name: "self-reference in auth_scopes is rejected",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"eduid": {
						AuthProvider: model.AuthProviderOpenID4VP,
						AuthScopes: map[string]model.AuthScopeEntry{
							"pid":   {AuthClaims: []string{"given_name"}},
							"eduid": {AuthClaims: []string{"given_name"}},
						},
					},
				}},
			},
			shouldError:   true,
			errorContains: "auth_scopes_self_reference",
		},
		{
			name: "no self-reference passes",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"eduid": {
						AuthProvider: model.AuthProviderOpenID4VP,
						AuthScopes: map[string]model.AuthScopeEntry{
							"pid": {AuthClaims: []string{"given_name"}},
						},
					},
				}},
			},
			shouldError:   false,
			errorContains: "",
		},
		{
			name: "empty datastore passes",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{}},
			},
			shouldError:   false,
			errorContains: "",
		},
		{
			name: "multiple credentials with no self-reference passes",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"diploma": {
						AuthProvider: model.AuthProviderOpenID4VP,
						AuthScopes: map[string]model.AuthScopeEntry{
							"pid": {AuthClaims: []string{"given_name", "family_name"}},
						},
					},
				}},
			},
			shouldError:   false,
			errorContains: "",
		},
		{
			name: "openid4vp with empty auth_claims in scope entry is rejected",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"ehic": {
						AuthProvider: model.AuthProviderOpenID4VP,
						AuthScopes: map[string]model.AuthScopeEntry{
							"pid": {AuthClaims: []string{}},
						},
					},
				}},
			},
			shouldError:   true,
			errorContains: "auth_claims_required_for_auth_scope",
		},
		{
			name: "openid4vp without auth_scopes is rejected",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"ehic": {
						AuthProvider: model.AuthProviderOpenID4VP,
					},
				}},
			},
			shouldError:   true,
			errorContains: "auth_scopes_required_for_openid4vp",
		},
		{
			name: "openid4vp with top-level auth_claims is rejected",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"ehic": {
						AuthProvider: model.AuthProviderOpenID4VP,
						AuthScopes: map[string]model.AuthScopeEntry{
							"pid": {AuthClaims: []string{"given_name"}},
						},
						AuthClaims: []string{"given_name"},
					},
				}},
			},
			shouldError:   true,
			errorContains: "auth_claims_not_allowed_for_openid4vp",
		},
		{
			name: "multiple auth_scopes with different claims passes",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"ehic": {
						AuthProvider: model.AuthProviderOpenID4VP,
						AuthScopes: map[string]model.AuthScopeEntry{
							"pid":   {AuthClaims: []string{"given_name", "family_name", "birth_date"}},
							"eduid": {AuthClaims: []string{"given_name", "family_name", "date_of_birth"}},
						},
					},
				}},
			},
			shouldError: false,
		},
		{
			name: "saml without auth_claims is rejected",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"pid": {
						AuthProvider: model.AuthProviderSAML,
					},
				}},
			},
			shouldError:   true,
			errorContains: "auth_claims_required_for_identity_lookup",
		},
		{
			name: "saml with auth_scopes is rejected",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"pid": {
						AuthProvider: model.AuthProviderSAML,
						AuthClaims:   []string{"given_name"},
						AuthScopes: map[string]model.AuthScopeEntry{
							"pid": {AuthClaims: []string{"given_name"}},
						},
					},
				}},
			},
			shouldError:   true,
			errorContains: "auth_scopes_only_for_openid4vp",
		},
		{
			name: "saml with auth_claims passes",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"pid": {
						AuthProvider: model.AuthProviderSAML,
						AuthClaims:   []string{"given_name", "family_name"},
					},
				}},
			},
			shouldError: false,
		},
		{
			name: "oidc with auth_claims passes",
			ds: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					"pid": {
						AuthProvider: model.AuthProviderOIDC,
						AuthClaims:   []string{"given_name"},
					},
				}},
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.StructPartial(tt.ds)
			if tt.shouldError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestImagePNGValidator(t *testing.T) {
	validate, err := NewValidator()
	require.NoError(t, err)

	type testStruct struct {
		Path string `validate:"omitempty,image_png"`
	}

	// Helper: write a valid 1x1 PNG to a temp file.
	writePNG := func(t *testing.T) string {
		t.Helper()
		img := image.NewRGBA(image.Rect(0, 0, 1, 1))
		img.Set(0, 0, color.White)
		var buf bytes.Buffer
		require.NoError(t, png.Encode(&buf, img))
		p := filepath.Join(t.TempDir(), "img.png")
		require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o644)) // #nosec G306
		return p
	}

	t.Run("valid PNG", func(t *testing.T) {
		assert.NoError(t, validate.Struct(testStruct{Path: writePNG(t)}))
	})

	t.Run("empty is OK with omitempty", func(t *testing.T) {
		assert.NoError(t, validate.Struct(testStruct{Path: ""}))
	})

	t.Run("non-existent file", func(t *testing.T) {
		assert.Error(t, validate.Struct(testStruct{Path: "/no/such/file.png"}))
	})

	t.Run("not a PNG", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "text.png")
		require.NoError(t, os.WriteFile(p, []byte("hello"), 0o644)) // #nosec G306
		assert.Error(t, validate.Struct(testStruct{Path: p}))
	})

	t.Run("JPEG is rejected", func(t *testing.T) {
		// JPEG magic bytes
		p := filepath.Join(t.TempDir(), "fake.png")
		require.NoError(t, os.WriteFile(p, []byte("\xff\xd8\xff\xe0fake-jpeg"), 0o644)) // #nosec G306
		assert.Error(t, validate.Struct(testStruct{Path: p}))
	})
}

func TestSingleProofTypeValidator(t *testing.T) {
	validate, err := NewValidator()
	require.NoError(t, err)

	type Proofs struct {
		JWT         []string
		DIVP        []string
		Attestation string
	}

	type testStruct struct {
		Proofs *Proofs `validate:"single_proof_type"`
	}

	type testStructOmitempty struct {
		Proofs *Proofs `validate:"omitempty,single_proof_type"`
	}

	t.Run("only JWT", func(t *testing.T) {
		assert.NoError(t, validate.Struct(testStruct{
			Proofs: &Proofs{
				JWT: []string{"jwt1"},
			},
		}))
	})
	t.Run("only DIVP", func(t *testing.T) {
		assert.NoError(t, validate.Struct(testStruct{
			Proofs: &Proofs{
				DIVP: []string{"divp1"},
			},
		}))
	})
	t.Run("only Attestation", func(t *testing.T) {
		assert.NoError(t, validate.Struct(testStruct{
			Proofs: &Proofs{
				Attestation: "attest1",
			},
		}))
	})
	t.Run("multiple proof types is an error", func(t *testing.T) {
		err := validate.Struct(testStruct{
			Proofs: &Proofs{
				JWT:  []string{"jwt1"},
				DIVP: []string{"divp1"},
			},
		})
		assert.Error(t, err)
	})
	t.Run("nil Proofs pointer is valid (omitempty)", func(t *testing.T) {
		assert.NoError(t, validate.Struct(testStructOmitempty{
			Proofs: nil,
		}))
	})
	t.Run("Attestation with empty JWT and DIVP is valid", func(t *testing.T) {
		assert.NoError(t, validate.Struct(testStruct{
			Proofs: &Proofs{
				JWT:         []string{},
				DIVP:        []string{},
				Attestation: "attest1",
			},
		}))
	})
	t.Run("JWT with empty DIVP and Attestation is valid", func(t *testing.T) {
		assert.NoError(t, validate.Struct(testStruct{
			Proofs: &Proofs{
				JWT:         []string{"jwt1"},
				DIVP:        []string{},
				Attestation: "",
			},
		}))
	})
	t.Run("DIVP with empty JWT and Attestation is valid", func(t *testing.T) {
		assert.NoError(t, validate.Struct(testStruct{
			Proofs: &Proofs{
				JWT:         []string{},
				DIVP:        []string{"divp1"},
				Attestation: "",
			},
		}))
	})
	t.Run("Attestation with non-empty JWT is an error", func(t *testing.T) {
		err := validate.Struct(testStruct{
			Proofs: &Proofs{
				JWT:         []string{"jwt1"},
				DIVP:        []string{},
				Attestation: "attest1",
			},
		})
		assert.Error(t, err)
	})
	t.Run("DIVP with non-empty Attestation is an error", func(t *testing.T) {
		err := validate.Struct(testStruct{
			Proofs: &Proofs{
				JWT:         []string{},
				DIVP:        []string{"divp1"},
				Attestation: "attest1",
			},
		})
		assert.Error(t, err)
	})
	t.Run("JWT with non-empty DIVP is an error", func(t *testing.T) {
		err := validate.Struct(testStruct{
			Proofs: &Proofs{
				JWT:         []string{"jwt1"},
				DIVP:        []string{"divp1"},
				Attestation: "",
			},
		})
		assert.Error(t, err)
	})
}

func TestAPIAuth_RulesRequireAuth(t *testing.T) {
	validate, err := NewValidator()
	require.NoError(t, err)

	t.Run("inline rules without auth mode", func(t *testing.T) {
		cfg := model.APIAuth{
			Rules: []string{`(api (service apigw)(method GET)(path /api/v1/search)(subject alice))`},
		}
		err := validate.Struct(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_auth_rules_require_auth")
	})

	t.Run("rules_file without auth mode", func(t *testing.T) {
		cfg := model.APIAuth{
			RulesFile: "/etc/spocp/rules.txt",
		}
		err := validate.Struct(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_auth_rules_require_auth")
	})

	t.Run("rules with jwks enabled is valid", func(t *testing.T) {
		cfg := model.APIAuth{
			Rules: []string{`(api (service apigw)(method GET)(path /)(subject alice))`},
			JWKS: model.APIAuthJWKS{
				Enable:   true,
				JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
				Issuer:   "https://auth.example.com",
				Audience: "my-api",
			},
		}
		assert.NoError(t, validate.Struct(cfg))
	})

	t.Run("no rules and no auth is valid", func(t *testing.T) {
		cfg := model.APIAuth{}
		assert.NoError(t, validate.Struct(cfg))
	})

	t.Run("jwks and oidc are mutually exclusive", func(t *testing.T) {
		cfg := model.APIAuth{
			JWKS: model.APIAuthJWKS{
				Enable:   true,
				JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
				Issuer:   "https://auth.example.com",
				Audience: "my-api",
			},
			OIDC: model.APIAuthOIDC{
				Enable: true,
			},
		}
		err := validate.Struct(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_auth_jwks_oidc_exclusive")
	})
}

func TestAPIAuthJWKS_SourceValidation(t *testing.T) {
	validate, err := NewValidator()
	require.NoError(t, err)

	t.Run("enabled with jwks_url is valid", func(t *testing.T) {
		cfg := model.APIAuthJWKS{
			Enable:   true,
			JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
			Issuer:   "https://auth.example.com",
			Audience: "my-api",
		}
		assert.NoError(t, validate.Struct(cfg))
	})

	t.Run("enabled with jwks_file_path is valid", func(t *testing.T) {
		cfg := model.APIAuthJWKS{
			Enable:       true,
			JWKSFilePath: "/etc/jwks/keys.json",
			Issuer:       "https://auth.example.com",
			Audience:     "my-api",
		}
		assert.NoError(t, validate.Struct(cfg))
	})

	t.Run("enabled with neither source fails", func(t *testing.T) {
		cfg := model.APIAuthJWKS{
			Enable:   true,
			Issuer:   "https://auth.example.com",
			Audience: "my-api",
		}
		err := validate.Struct(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "jwks_source_required")
	})

	t.Run("enabled with both sources fails", func(t *testing.T) {
		cfg := model.APIAuthJWKS{
			Enable:       true,
			JWKSURL:      "https://auth.example.com/.well-known/jwks.json",
			JWKSFilePath: "/etc/jwks/keys.json",
			Issuer:       "https://auth.example.com",
			Audience:     "my-api",
		}
		err := validate.Struct(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "excluded_with")
	})

	t.Run("disabled with no sources is valid", func(t *testing.T) {
		cfg := model.APIAuthJWKS{
			Enable: false,
		}
		assert.NoError(t, validate.Struct(cfg))
	})

	t.Run("enabled without issuer fails", func(t *testing.T) {
		cfg := model.APIAuthJWKS{
			Enable:   true,
			JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
			Audience: "my-api",
		}
		err := validate.Struct(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required_if")
	})

	t.Run("enabled without audience fails", func(t *testing.T) {
		cfg := model.APIAuthJWKS{
			Enable:  true,
			JWKSURL: "https://auth.example.com/.well-known/jwks.json",
			Issuer:  "https://auth.example.com",
		}
		err := validate.Struct(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required_if")
	})
}
