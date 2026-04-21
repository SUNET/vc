package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SUNET/vc/pkg/model"
)

type elmClient struct {
	client              *Client
	documents           map[string]*model.CompleteDocument
	credentialType      string
	exampleELM          []map[string]any
	exampleELMFilePaths []string
}

func NewELMClient(ctx context.Context, client *Client) (*elmClient, error) {
	elmClient := &elmClient{
		client:     client,
		documents:  map[string]*model.CompleteDocument{},
		exampleELM: []map[string]any{},
		exampleELMFilePaths: []string{
			filepath.Join("../../../standards", "elm_3_2.json"),
		},
		credentialType: "elm",
	}

	if err := elmClient.loadExampleFiles(); err != nil {
		return nil, fmt.Errorf("read document data file: %w", err)
	}

	return elmClient, nil
}

func (c *elmClient) makeSourceData(sourceFilePath string) error {
	for pidNumber, id := range c.client.identities {
		c.documents[pidNumber] = &model.CompleteDocument{}

		documentData, err := c.getOneDocumentData(pidNumber)
		if err != nil {
			return fmt.Errorf("get document data: %w", err)
		}
		c.documents[pidNumber].DocumentData = documentData

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: "ELM:00001",
			DocumentVersion: "1.0.0",
			VCT:             model.CredentialTypeUrnEudiElm1,
			Scope:           "elm",
			DocumentID:      fmt.Sprintf("document_id_elm_%s", pidNumber),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_elm_%s", pidNumber),
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
					"description": "European Learning Model",
				},
				"sv": map[string]any{
					"beskrivning": "European Learning Model",
				},
			},
		}

		c.documents[pidNumber].Identities = id.Identities

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"
	}
	return nil
}

func (c *elmClient) save2Disk() error {
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

func (c *elmClient) loadExampleFiles() error {
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

func (c *elmClient) getOneDocumentData(pidNumber string) (map[string]any, error) {
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
