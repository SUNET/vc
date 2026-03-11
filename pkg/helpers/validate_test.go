package helpers

import (
	"testing"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
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
						"value":           "",
					},
					{
						"field":           "schema",
						"namespace":       "schema",
						"type":            "ptr",
						"validation":      "required",
						"validationParam": "",
						"value":           (*model.IdentitySchema)(nil),
					},
					{
						"field":           "family_name",
						"namespace":       "family_name",
						"type":            "string",
						"validation":      "required",
						"validationParam": "",
						"value":           "",
					},
					{
						"field":           "given_name",
						"namespace":       "given_name",
						"type":            "string",
						"validation":      "required",
						"validationParam": "",
						"value":           "",
					},
					{
						"field":           "birth_date",
						"namespace":       "birth_date",
						"type":            "string",
						"validation":      "required",
						"validationParam": "",
						"value":           "",
					},
				},
			},
		},
		{
			name: "ok",
			have: &model.Identity{
				AuthenticSourcePersonID: "person-123",
				Schema: &model.IdentitySchema{
					Name:    "SE",
					Version: "1.0.0",
				},
				FamilyName: "Doe",
				GivenName:  "John",
				BirthDate:  "1970-01-01",
			},
			want: nil,
		},
		{
			name: "wrong datetime format",
			have: &model.Identity{
				AuthenticSourcePersonID: "person-123",
				Schema: &model.IdentitySchema{
					Name: "SE",
				},
				FamilyName: "Doe",
				GivenName:  "John",
				BirthDate:  "1972-10-27 10:15:31.432635902 +0000 UTC",
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
						"value":           "1972-10-27 10:15:31.432635902 +0000 UTC",
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
						"value":           "",
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
						Schema: &model.IdentitySchema{
							Name: "SE",
						},
						FamilyName: "Doe",
						GivenName:  "John",
						BirthDate:  "1972-10-27",
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
						Schema: &model.IdentitySchema{
							Name: "SE",
						},
						FamilyName: "Doe",
						GivenName:  "John",
						BirthDate:  "1972-10-27 10:15:31.432635902 +0000 UTC",
					},
				},
			},
			want: &Error{
				Title: "validation_error",
				Err: []map[string]any{{
					"field":           "birth_date",
					"namespace":       "ID[0].birth_date",
					"type":            "string",
					"validation":      "datetime",
					"validationParam": "2006-01-02",
					"value":           "1972-10-27 10:15:31.432635902 +0000 UTC",
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
		name        string
		common      model.Common
		shouldError bool
	}{
		{
			name: "self-reference in auth_scopes is rejected",
			common: model.Common{
				CredentialConstructor: map[string]*model.CredentialConstructor{
					"eduid": {
						AuthMethod: "openid4vp",
						AuthScopes: []string{"pid", "eduid"},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "no self-reference passes",
			common: model.Common{
				CredentialConstructor: map[string]*model.CredentialConstructor{
					"eduid": {
						AuthMethod: "openid4vp",
						AuthScopes: []string{"pid"},
					},
				},
			},
			shouldError: false,
		},
		{
			name: "empty auth_scopes passes",
			common: model.Common{
				CredentialConstructor: map[string]*model.CredentialConstructor{
					"pid": {
						AuthMethod: "basic",
					},
				},
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.StructPartial(tt.common)
			if tt.shouldError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "auth_scopes_self_reference")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}