package main

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func GeneratePDA1Document(t *testing.T) map[string]any {
	// Create a document with all required fields per schema_pda1.json
	document := map[string]any{
		"social_security_pin": "12345",
		"nationality":         []string{"SE"},
		"details_of_employment": []map[string]any{
			{
				"type_of_employment": "01",
				"name":               "SUNET",
				"address": map[string]any{
					"street":    "Tulegatan 11",
					"post_code": "12354",
					"town":      "Stockholm",
					"country":   "SE",
				},
				"ids_of_employer": []map[string]any{
					{
						"employer_id": "SE:1234",
						"type_of_id":  "01",
					},
				},
			},
		},
		"places_of_work": []map[string]any{
			{
				"a_fixed_place_of_work_exist": false,
				"country_work":                "SE",
				"place_of_work": []map[string]any{
					{
						"company_vessel_name":  "M/S Transpaper",
						"flag_state_home_base": "Göteborg",
						"ids_of_company": []map[string]any{
							{
								"company_id": "SE:1234",
								"type_of_id": "01",
							},
						},
						"address": map[string]any{
							"street":    "vägen 1",
							"post_code": "1235",
							"town":      "Göteborg",
						},
					},
				},
			},
		},
		"decision_legislation_applicable": map[string]any{
			"member_state_which_legislation_applies": "SE",
			"transitional_rule_apply":                false,
			"starting_date":                          "1970-01-01",
			"ending_date":                            "2038-01-19",
		},
		"status_confirmation":              "02",
		"unique_number_of_issued_document": "SE1234",
		"competent_institution": map[string]any{
			"institution_id":   "SE:12345",
			"institution_name": "test",
			"country_code":     "SE",
		},
	}

	return document
}

var mockPDA1JSON = `{
	"person": {
		"forename": "Magnus",
		"family_name": "Svensson",
		"date_of_birth": "1986-02-23",
		"other_elements": {
			"sex": "01",
			"forename_at_birth": "Magnus",
			"family_name_at_birth": "Svensson"
		}
	},
	"social_security_pin": "12345",
	"nationality": [
		"SE"
	],
	"details_of_employment": [
		{
			"type_of_employment": "01",
			"name": "SUNET",
			"address": {
				"street": "Tulegatan 11",
				"post_code": "12354",
				"town": "Stockholm",
				"country": "SE"
			},
			"ids_of_employer": [
				{
					"employer_id": "SE:1234",
					"type_of_id": "01"
				}
			]
		}
	],
	"places_of_work": [
		{
			"a_fixed_place_of_work_exist": false,
			"country_work": "SE",
			"place_of_work": [
				{
					"company_vessel_name": "M/S Transpaper",
					"flag_state_home_base": "Göteborg",
					"ids_of_company": [
						{
							"company_id": "SE:1234",
							"type_of_id": "01"
						}
					],
					"address": {
						"street": "vägen 1",
						"post_code": "1235",
						"town": "Göteborg"
					}
				}
			]
		}
	],
	"decision_legislation_applicable": {
		"member_state_which_legislation_applies": "SE",
		"transitional_rule_apply": false,
		"starting_date": "1970-01-01",
		"ending_date": "2038-01-19"
	},
	"status_confirmation": "02",
	"unique_number_of_issued_document": "SE1234",
	"competent_institution": {
		"institution_id": "SE:12345",
		"institution_name": "test",
		"country_code": "SE"
	}
}`

var mockEmptyPDA1JSON = `{}`

var mockTopLevelPDA1JSON = `{
"social_security_pin": "",
		"details_of_employment": "",
		"unique_number_of_issued_document": "",
		"competent_institution": "",
		"nationality": "",
		"places_of_work": "",
		"decision_legislation_applicable": "",
		"status_confirmation": ""
}`

func mockPDA1Map(t *testing.T, jsonString string) map[string]any {
	docMap := map[string]any{}

	err := json.Unmarshal([]byte(jsonString), &docMap)
	assert.NoError(t, err)

	return docMap
}

func TestSchemaValidation(t *testing.T) {
	tts := []struct {
		name      string
		payload   *model.CompleteDocument
		wantErr   bool
		wantTitle string
	}{
		{
			name: "happy-from struct to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../../standards/schema_pda1.json",
				},
				DocumentData: GeneratePDA1Document(t),
			},
			wantErr: false,
		},
		{
			name: "happy-from string to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../../standards/schema_pda1.json",
				},
				DocumentData: mockPDA1Map(t, mockPDA1JSON),
			},
			wantErr: false,
		},
		{
			name: "unhappy-empty document",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../../standards/schema_pda1.json",
				},
				DocumentData: mockPDA1Map(t, mockEmptyPDA1JSON),
			},
			wantErr:   true,
			wantTitle: "document_data_schema_error",
		},
		{
			name: "unhappy-top level",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../../standards/schema_pda1.json",
				},
				DocumentData: mockPDA1Map(t, mockTopLevelPDA1JSON),
			},
			wantErr:   true,
			wantTitle: "document_data_schema_error",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			got := helpers.ValidateDocumentData(ctx, tt.payload, logger.NewSimple("test"))

			if tt.wantErr {
				assert.Error(t, got)
				var helperErr *helpers.Error
				if assert.ErrorAs(t, got, &helperErr) {
					assert.Equal(t, tt.wantTitle, helperErr.Title)
				}
			} else {
				assert.NoError(t, got)
			}
		})
	}
}
