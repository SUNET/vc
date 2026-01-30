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
