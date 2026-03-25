package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/xuri/excelize/v2"
)

type clients interface {
	makeSourceData(sourceFilePath string) error
	save2Disk() error
}

type Client struct {
	cfg            *model.Cfg
	identities     map[string]*vcclient.UploadRequest
	vcClient       *vcclient.Client
	vcClientConfig *vcclient.Config
	log            *logger.Log

	pda1Client            clients
	ehicClient            clients
	pidClient             clients
	pidUserClient         clients
	elmClient             clients
	diplomaClient         clients
	MicroCredentialClient clients
	eduidClient           clients
}

func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	client := &Client{
		cfg:        cfg,
		identities: map[string]*vcclient.UploadRequest{},
		vcClientConfig: &vcclient.Config{
			ApigwURL: cfg.MockAS.DatastoreURL,
		},
		log: log.New("bootstrapper"),
	}

	var err error
	client.vcClient, err = vcclient.New(client.vcClientConfig, client.log)
	if err != nil {
		return nil, fmt.Errorf("new datastore client: %w", err)
	}

	client.pda1Client, err = NewPDA1Client(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new pda1 client: %w", err)
	}

	client.ehicClient, err = NewEHICClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new ehic client: %w", err)
	}

	client.pidClient, err = NewPIDClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new pid client: %w", err)
	}

	client.elmClient, err = NewELMClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new elm client: %w", err)
	}

	client.diplomaClient, err = NewDiplomaClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new diploma client: %w", err)
	}

	client.MicroCredentialClient, err = NewMicroCredentialClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new micro credential client: %w", err)
	}

	client.eduidClient, err = NewEduIDClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new eduid client: %w", err)
	}

	client.pidUserClient, err = NewIDPUserClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("new user client: %w", err)
	}

	for _, credentialType := range []string{"idp_user"} {
		jsonPath := filepath.Join("../../../bootstrapping", fmt.Sprintf("%s.json", credentialType))
		if err := client.userUpload(ctx, jsonPath); err != nil {
			client.log.Error(err, "user upload failed", "credentialType", credentialType)
		}
	}

	for _, credentialType := range []string{
		"ehic",
		"pda1",
		"elm",
		"diploma",
		"microcredential",
		"pid-1-5",
		"pid-1-8",
		"eduid",
	} {
		jsonPath := filepath.Join("../../../bootstrapping", fmt.Sprintf("%s.json", credentialType))
		if err := client.documentUploader(ctx, jsonPath); err != nil {
			client.log.Error(err, "document upload failed", "credentialType", credentialType)
		}
	}

	return client, nil
}

func (c *Client) makeIdentities(sourceFilePath string) error {
	fs, err := excelize.OpenFile(sourceFilePath)
	if err != nil {
		c.log.Error(err, "cant open file")
		return err
	}
	defer func() {
		// Close the spreadsheet.
		if err := fs.Close(); err != nil {
			c.log.Error(err, "cant close file")
		}
	}()

	// Get value from cell by given worksheet name and cell reference.
	pidRows, err := fs.GetRows("PID")
	if err != nil {
		c.log.Error(err, "failed to get PID rows from spreadsheet")
		return err
	}

	for _, row := range pidRows {
		if row[0] == "" || row[0] == "pid_id" {
			continue
		}
		dateOfBirth := strings.ReplaceAll(row[8], "/", "-")

		c.identities[row[0]] = &vcclient.UploadRequest{
			DocumentDataVersion: "1.0.0",
			Identities: []model.Identity{
				{
					AuthenticSourcePersonID: fmt.Sprintf("authentic_source_person_id_%s", row[0]),
					Schema: &model.IdentitySchema{
						Name:    "DefaultSchema",
						Version: "",
					},
					FamilyName:       row[6],
					GivenName:        row[7],
					BirthDate:        dateOfBirth,
					BirthPlace:       "Tulegatan 11",
					Nationality:      []string{"SE"},
					ExpiryDate:       "2033-01-01",
					IssuingAuthority: "SUNET",
					IssuingCountry:   "SE",
				},
			},
		}

	}

	return nil
}

func (c *Client) shouldUpload(id string) bool {
	if slices.Contains(c.cfg.MockAS.BootstrapUsers, id) {
		return true
	}

	if len(c.cfg.MockAS.BootstrapUsers) == 0 {
		return true
	}

	return false
}

func (c *Client) documentUploader(ctx context.Context, jsonPath string) error {
	b, err := os.ReadFile(filepath.Clean(jsonPath))
	if err != nil {
		return err
	}

	requests := map[string]*vcclient.UploadRequest{}
	if err := json.Unmarshal(b, &requests); err != nil {
		return err
	}

	for id, request := range requests {
		if c.shouldUpload(id) {
			resp, err := c.vcClient.APIGW.Root.Upload(ctx, request)
			if err != nil {
				c.log.Error(err, "Upload", "resp", resp)
				return err
			}
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}

			c.log.Debug("Upload", "resp", resp.StatusCode)
		}
	}

	return nil
}

func (c *Client) userUpload(ctx context.Context, jsonPath string) error {
	b, err := os.ReadFile(filepath.Clean(jsonPath))
	if err != nil {
		return err
	}

	requests := map[string]*vcclient.AddPIDRequest{}
	if err := json.Unmarshal(b, &requests); err != nil {
		return err
	}
	c.log.Debug("userUpload", "document count", len(requests))

	for id, request := range requests {
		if c.shouldUpload(id) {
			resp, err := c.vcClient.APIGW.User.AddPID(ctx, request)
			if err != nil {
				c.log.Error(err, "User Upload", "resp", resp)
				return err
			}
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			c.log.Debug("User Upload", "resp", resp.StatusCode)
		}
	}

	return nil
}
