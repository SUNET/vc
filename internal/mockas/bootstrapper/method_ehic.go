package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/socialsecurity"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/xuri/excelize/v2"
)

type ehicClient struct {
	client         *Client
	documents      map[string]*vcclient.UploadRequest
	credentialType string
}

func NewEHICClient(ctx context.Context, client *Client) (*ehicClient, error) {
	ehicClient := &ehicClient{
		client:         client,
		documents:      map[string]*vcclient.UploadRequest{},
		credentialType: "ehic",
	}
	return ehicClient, nil
}

func (c *ehicClient) makeSourceData(sourceFilePath string) error {
	f, err := excelize.OpenFile(sourceFilePath)
	if err != nil {
		return err
	}
	defer func() {
		// Close the spreadsheet.
		if err := f.Close(); err != nil {
			c.client.log.Error(err, "failed to close spreadsheet file")
		}
	}()

	ehicRows, err := f.GetRows("EHIC")
	if err != nil {
		return err
	}

	for _, row := range ehicRows {
		pidNumber := row[0]
		if pidNumber == "" || pidNumber == "pid_id" {
			continue
		}

		c.documents[pidNumber] = &vcclient.UploadRequest{}

		SocialSecurityPin := row[4]
		startDate := row[5]
		endDate := row[6]

		CardNumber := row[7]
		InstitutionID := row[8]
		//InstitutionName := row[9]
		InstitutionCountry := row[10]

		identity, ok := c.client.identities[pidNumber]
		if !ok {
			return fmt.Errorf("no user found for pid %s", pidNumber)
		}

		document := &socialsecurity.EHICDocument{
			PersonalAdministrativeNumber: SocialSecurityPin,
			IssuingAuthority: socialsecurity.IssuingAuthority{
				ID:   InstitutionID,
				Name: "SUNET",
			},
			IssuingCountry: InstitutionCountry,
			DateOfExpiry:   endDate,
			DateOfIssuance: startDate,
			DocumentNumber: CardNumber,
			StartingDate:   time.Now().Format("2006-01-02"),
			EndingDate:     time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
			AuthenticSource: socialsecurity.AuthenticSource{
				ID:   InstitutionID,
				Name: "SUNET",
			},
		}

		var err error
		c.documents[pidNumber].DocumentData, err = document.Marshal()
		if err != nil {
			return err
		}

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: row[2],
			DocumentVersion: "1.0.0",
			VCT:             model.CredentialTypeUrnEudiEhic1,
			Scope:           "ehic",
			DocumentID:      fmt.Sprintf("document_id_ehic_%s", row[0]),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_ehic_%s", row[0]),
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
					"description": "European Health Insurance Card",
				},
				"sv": map[string]any{
					"beskrivning": "Europeiskt sjukförsäkringskort",
				},
			},
		}
		c.documents[pidNumber].Identities = identity.Identities

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"
	}

	return nil
}

func (c *ehicClient) save2Disk() error {
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
