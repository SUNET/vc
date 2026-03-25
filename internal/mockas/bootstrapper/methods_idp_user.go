package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"
)

type idpUsersClient struct {
	client            *Client
	documents         map[string]*vcclient.AddPIDRequest
	credentialType    string
	exampleCredential []map[string]any
	exampleFilePaths  []string
}

func NewIDPUserClient(ctx context.Context, client *Client) (*idpUsersClient, error) {
	usersClient := &idpUsersClient{
		client:            client,
		documents:         map[string]*vcclient.AddPIDRequest{},
		exampleCredential: []map[string]any{},
		exampleFilePaths:  []string{},
		credentialType:    "idp_user",
	}

	return usersClient, nil
}

func (c *idpUsersClient) makeSourceData(sourceFilePath string) error {
	for pidNumber, id := range c.client.identities {

		c.documents[pidNumber] = &vcclient.AddPIDRequest{
			Username: strings.ToLower(id.Identities[0].FamilyName),
			Password: strings.ToLower(id.Identities[0].FamilyName),
			Identity: &id.Identities[0],
			Meta: &model.MetaData{
				AuthenticSource: "PID_Provider:00001",
				VCT:             "not_applicable",
				Scope:           "idp_user",
				DocumentVersion: "1.0.0",
				DocumentID:      fmt.Sprintf("idp_user_%s", pidNumber),
			},
		}
	}

	return nil
}

func (c *idpUsersClient) save2Disk() error {
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
