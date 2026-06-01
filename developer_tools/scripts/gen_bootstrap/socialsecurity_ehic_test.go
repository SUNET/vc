package main

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func generateEHICDocument(t *testing.T) map[string]any {
	document := map[string]any{
		// JWT required fields
		"vct": "urn:eudi:ehic:1",
		"jti": "urn:uuid:12345678-1234-1234-1234-123456789012",
		"sub": "did:example:subject123",
		"iss": "https://issuer.example.com",
		"iat": time.Now().Unix(),
		"cnf": map[string]any{
			"jwk": map[string]any{
				"kty": "EC",
				"crv": "P-256",
				"x":   "example-x-coordinate",
				"y":   "example-y-coordinate",
			},
		},
		// EHIC specific fields
		"personal_administrative_number": "123123123",
		"issuing_authority": map[string]any{
			"id":   "1231231",
			"name": "SUNET",
		},
		"issuing_country":  "SE",
		"date_of_expiry":   "2038-01-19",
		"date_of_issuance": "2021-01-19",
		"document_number":  "123123123",
		"authentic_source": map[string]any{
			"id":   "SE-EHIC-001",
			"name": "Swedish Social Insurance Agency",
		},
	}

	return document
}

func mockEHICMap(t *testing.T) map[string]any {
	return generateEHICDocument(t)
}

func TestEHICSchemaValidation(t *testing.T) {
	tts := []struct {
		name    string
		payload *model.CompleteDocument
		want    error
	}{
		{
			name: "from struct to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "https://demo-issuer.wwwallet.org/public/creds/ehic/european-health-insurance-card-schema-dc4eu-01.json",
				},
				DocumentData: generateEHICDocument(t),
			},
			want: nil,
		},
		{
			name: "from string to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "https://demo-issuer.wwwallet.org/public/creds/ehic/european-health-insurance-card-schema-dc4eu-01.json",
				},
				DocumentData: mockEHICMap(t),
			},
			want: nil,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			got := helpers.ValidateDocumentData(ctx, tt.payload, logger.NewSimple("test"))

			assert.Equal(t, tt.want, got)
		})
	}
}
