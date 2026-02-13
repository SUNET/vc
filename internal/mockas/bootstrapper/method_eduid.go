package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"vc/pkg/model"
	"vc/pkg/vcclient"

	"github.com/brianvoe/gofakeit/v7"
)

type eduidClient struct {
	client         *Client
	documents      map[string]*vcclient.UploadRequest
	credentialType string
	pidUsers       map[string]*vcclient.AddPIDRequest
}

func NewEduIDClient(ctx context.Context, client *Client) (*eduidClient, error) {
	c := &eduidClient{
		client:         client,
		documents:      map[string]*vcclient.UploadRequest{},
		credentialType: "eduid",
	}

	return c, nil
}

func (c *eduidClient) readPidUserFile(sourceFilePath string) error {
	f, err := os.Open(filepath.Clean(sourceFilePath))
	if err != nil {
		return fmt.Errorf("open pid user file: %w", err)
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&c.pidUsers); err != nil {
		return fmt.Errorf("decode pid user file: %w", err)
	}

	return nil
}

func (c *eduidClient) makeSourceData(sourceFilePath string) error {
	if err := c.readPidUserFile(sourceFilePath); err != nil {
		return fmt.Errorf("read pid user file: %w", err)
	}

	for pidNumber, id := range c.pidUsers {
		c.documents[pidNumber] = &vcclient.UploadRequest{}

		// Calculate age from birthdate
		birthDate, _ := time.Parse("2006-01-02", id.Identity.BirthDate)
		age := time.Now().Year() - birthDate.Year()
		if time.Now().YearDay() < birthDate.YearDay() {
			age--
		}

		documentData := map[string]any{
			// Mandatory fields
			"given_name":  id.Identity.GivenName,
			"family_name": id.Identity.FamilyName,
			"birthdate":   id.Identity.BirthDate,
			"place_of_birth": map[string]any{
				"locality": id.Identity.BirthPlace,
				"region":   gofakeit.State(),
				"country":  id.Identity.Nationality[0],
			},
			"issuing_authority": id.Identity.IssuingAuthority,
			"issuing_country":   id.Identity.IssuingCountry,
			"nationalities":     id.Identity.Nationality,

			"issuing_jurisdiction": "SUNET",
			"trust_anchor":         "https://ta.oidf.sunet.se",

			// Date fields
			"date_of_expiry":   time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
			"expiry_date":      time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02"),
			"date_of_issuance": time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),

			// Internal/metadata fields
			"authentic_source_person_id": id.Identity.AuthenticSourcePersonID,

			// Document fields
			"document_number":                gofakeit.UUID(),
			"personal_administrative_number": gofakeit.Numerify("######-####"),
			"picture":                        "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAFElEQVQYV2P8z8DwHwYGBgZGMAEADigBCCGZkB0AAAAASUVORK5CYII=",

			// Birth names
			"birth_family_name": gofakeit.LastName(),
			"birth_given_name":  gofakeit.FirstName(),

			// Personal info
			"sex":          strconv.Itoa(gofakeit.Number(1, 2)), // 1=male, 2=female
			"email":        gofakeit.Email(),
			"phone_number": gofakeit.Phone(),

			// Address
			"address": map[string]any{
				"locality":       gofakeit.City(),
				"country":        id.Identity.IssuingCountry,
				"formatted":      gofakeit.Address().Address,
				"postal_code":    gofakeit.Zip(),
				"house_number":   gofakeit.StreetNumber(),
				"street_address": gofakeit.Street(),
				"region":         gofakeit.State(),
			},

			// Age attributes
			"age_equal_or_over": map[string]any{
				"14": age >= 14,
				"16": age >= 16,
				"18": age >= 18,
				"21": age >= 21,
				"65": age >= 65,
			},
			"age_in_years":   age,
			"age_birth_year": birthDate.Year(),
		}

		c.documents[pidNumber].DocumentData = documentData

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: "eduID_Provider:00001",
			DocumentVersion: "1.0.0",
			VCT:             model.CredentialTypeUrnEduID1,
			Scope:           "eduid",
			DocumentID:      fmt.Sprintf("document_id_eduid_%s", pidNumber),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_eduid_%s", pidNumber),
				ValidUntil: 0,
			},
			Revocation:                &model.Revocation{},
			CredentialValidFrom:       0,
			CredentialValidTo:         0,
			DocumentDataValidationRef: "",
		}

		c.documents[pidNumber].DocumentDisplay = &model.DocumentDisplay{
			Version: "1.0.0",
			Type:    "secure",
			DescriptionStructured: map[string]any{
				"en": map[string]any{
					"description": "eduID Credential",
				},
				"sv": map[string]any{
					"beskrivning": "eduID-legitimation",
				},
			},
		}

		c.documents[pidNumber].Identities = []model.Identity{*id.Identity}

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"
	}

	return nil
}

func (c *eduidClient) save2Disk() error {
	b, err := json.MarshalIndent(c.documents, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join("../../../bootstrapping", fmt.Sprintf("%s.json", c.credentialType))

	if err := os.WriteFile(filepath.Clean(filePath), b, 0600); err != nil {
		return err
	}

	return nil
}
