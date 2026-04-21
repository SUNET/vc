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

	"github.com/google/uuid"
	"github.com/xuri/excelize/v2"
)

type pda1Client struct {
	client         *Client
	documents      map[string]*vcclient.UploadRequest
	credentialType string
}

func NewPDA1Client(ctx context.Context, client *Client) (*pda1Client, error) {
	c := &pda1Client{
		client:         client,
		documents:      map[string]*vcclient.UploadRequest{},
		credentialType: "pda1",
	}

	return c, nil
}

func (c *pda1Client) makeSourceData(sourceFilePath string) error {
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

	pda1Rows, err := f.GetRows("PDA1")
	if err != nil {
		return err
	}

	for _, row := range pda1Rows {
		pidNumber := row[0]
		if pidNumber == "" || pidNumber == "pid_id" || pidNumber == "pid_id (Spalte H, nach pda1_issuing_country)" {
			continue
		}

		c.documents[pidNumber] = &vcclient.UploadRequest{}

		identity, ok := c.client.identities[pidNumber]
		if !ok {
			return fmt.Errorf("no user found for pid %s", pidNumber)
		}

		document := &socialsecurity.PDA1Document{
			PersonalAdministrativeNumber: row[6],
			Employer: socialsecurity.Employer{
				ID:      row[10],
				Name:    row[11],
				Country: "SE",
			},
			WorkAddress: socialsecurity.WorkAddress{
				Formatted:      row[12],
				Street_address: "Tulegatan",
				House_number:   "11",
				Postal_code:    row[14],
				Locality:       row[13],
				Region:         row[13],
				Country:        row[15],
			},
			IssuingAuthority: socialsecurity.IssuingAuthority{
				ID:   "01",
				Name: "SUNET",
			},
			LegislationCountry: "EU",
			StatusConfirmation: "02",
			IssuingCountry:     "EU",
			DateOfExpiry:       row[29],
			DateOfIssuance:     row[28],
			DocumentNumber:     row[6], // something better?
			StartingDate:       time.Now().Format("2006-01-02"),
			EndingDate:         time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
			AuthenticSource: socialsecurity.AuthenticSource{
				ID:   uuid.NewString(),
				Name: "SUNET",
			},
		}

		var err error
		c.documents[pidNumber].DocumentData, err = document.Marshal()
		if err != nil {
			return err
		}

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: row[3],
			DocumentVersion: "1.0.0",
			VCT:             model.CredentialTypeUrnEudiPda11,
			Scope:           "pda1",
			DocumentID:      fmt.Sprintf("document_id_pda1_%s", row[0]),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_pda1_%s", row[0]),
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
					"description": "PDA1 Document",
				},
				"sv": map[string]any{
					"beskrivning": "PDA1 Dokument",
				},
			},
		}

		c.documents[pidNumber].Identities = identity.Identities

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"

	}

	return nil
}

func (c *pda1Client) save2Disk() error {
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
