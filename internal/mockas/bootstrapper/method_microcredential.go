package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"
)

type MicroCredentialClient struct {
	client              *Client
	documents           map[string]*vcclient.UploadRequest
	credentialType      string
	exampleELM          []map[string]any
	exampleELMFilePaths []string
}

func NewMicroCredentialClient(ctx context.Context, client *Client) (*MicroCredentialClient, error) {
	microCredentialClient := &MicroCredentialClient{
		client:     client,
		documents:  map[string]*vcclient.UploadRequest{},
		exampleELM: []map[string]any{},
		exampleELMFilePaths: []string{
			filepath.Join("../../../standards", "education_credential", "micro_credential", "uvh_fvhz_microcredential_full.json"),
		},
		credentialType: "microcredential",
	}

	if err := microCredentialClient.loadExampleFiles(); err != nil {
		return nil, err
	}

	return microCredentialClient, nil
}

func (c *MicroCredentialClient) makeSourceData(sourceFilePath string) error {
	for pidNumber, id := range c.client.identities {
		c.documents[pidNumber] = &vcclient.UploadRequest{}

		documentData, err := c.getOneDocumentData(pidNumber)
		if err != nil {
			return fmt.Errorf("get document data: %w", err)
		}
		c.documents[pidNumber].DocumentData = documentData

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: "MICROCREDENTIAL:00001",
			DocumentVersion: "1.0.0",
			VCT:             model.CredentialTypeUrnEudiMicroCredential1,
			Scope:           "microcredential",
			DocumentID:      fmt.Sprintf("document_id_microcredential_%s", pidNumber),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_microcredential_%s", pidNumber),
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
					"description": "MicroCredential",
				},
				"sv": map[string]any{
					"beskrivning": "MicroCredential",
				},
			},
		}

		c.documents[pidNumber].Identities = id.Identities

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"
	}

	return nil
}

func (c *MicroCredentialClient) save2Disk() error {
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

func (c *MicroCredentialClient) loadExampleFiles() error {
	for _, filePath := range c.exampleELMFilePaths {
		b, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			return err
		}

		doc := map[string]any{}
		if err := json.Unmarshal(b, &doc); err != nil {
			return err
		}

		c.exampleELM = append(c.exampleELM, doc)
	}

	return nil
}

func (c *MicroCredentialClient) getOneDocumentData(pidNumber string) (map[string]any, error) {
	if len(c.exampleELM) == 0 {
		return nil, fmt.Errorf("no example ELM files loaded")
	}
	if len(c.exampleELM) == 1 {
		return c.exampleELM[0], nil
	} else if len(c.exampleELM) > 1 {
		return nil, fmt.Errorf("multiple example ELM files not supported yet")
	}

	return nil, nil

}
