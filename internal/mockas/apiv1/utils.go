package apiv1

import (
	"context"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/brianvoe/gofakeit/v6"
)

type person struct {
	sa        *gofakeit.PersonInfo
	birthDate string
}

func (p *person) new() {
	p.sa = gofakeit.Person()
	p.birthDate = gofakeit.Date().Format("2006-01-02")
}

type uploadMock struct {
	Meta         *model.MetaData `json:"meta" validate:"required"`
	Identities   []string        `json:"identities,omitempty"`
	DocumentData map[string]any  `json:"document_data" validate:"required"`
}

func (c *Client) mockOne(ctx context.Context, data *vcclient.MockNextRequest) (*uploadMock, error) {
	c.log.Debug("mockOne")
	person := &person{}
	person.new()

	if data.AuthenticSourcePersonID == "" {
		data.AuthenticSourcePersonID = gofakeit.UUID()
	}

	if data.GivenName == "" {
		data.GivenName = person.sa.FirstName
	}

	if data.FamilyName == "" {
		data.FamilyName = person.sa.LastName
	}

	if data.BirthDate == "" {
		data.BirthDate = person.birthDate
	}

	if data.CollectID == "" {
		data.CollectID = gofakeit.UUID()
	}

	if data.DocumentID == "" {
		data.DocumentID = gofakeit.UUID()
	}

	if data.IdentitySchemaName == "" {
		data.IdentitySchemaName = "DefaultSchema"
	}

	if data.AuthenticSource == "" {
		data.AuthenticSource = gofakeit.Company()
	}

	meta := &model.MetaData{
		AuthenticSource: data.AuthenticSource,
		DocumentID:      data.DocumentID,
	}

	identities := []string{
		data.AuthenticSourcePersonID,
	}

	mockUpload := &uploadMock{
		Meta:       meta,
		Identities: identities,
	}

	var err error
	switch data.VCT {
	case model.CredentialTypeUrnEudiPda11:
		mockUpload.Meta.Scope = "pda1"
		mockUpload.DocumentData, err = c.PDA1.random(ctx, person)
		if err != nil {
			return nil, err
		}
		mockUpload.Meta.DocumentDataValidationRef = "file://../../standards/schema_pda1.json"
	case model.CredentialTypeUrnEudiEhic1:
		mockUpload.Meta.Scope = "ehic"
		mockUpload.DocumentData, err = c.EHIC.random(ctx, person)
		if err != nil {
			return nil, err
		}
		mockUpload.Meta.DocumentDataValidationRef = "file://../../standards/schema_ehic.json"
	case model.CredentialTypeUrnEudiPid1:
		mockUpload.Meta.Scope = "pid"
		mockUpload.DocumentData, err = c.PID.random(ctx, person)
		if err != nil {
			return nil, err
		}

	case model.CredentialTypeUrnEudiElm1:
		mockUpload.Meta.Scope = "elm"
		mockUpload.DocumentData, err = c.ELM.random(ctx, person)
		if err != nil {
			return nil, err
		}
	default:
		return nil, helpers.ErrNoKnownVCT
	}

	c.log.Debug("2")
	if err := helpers.CheckSimple(mockUpload); err != nil {
		c.log.Debug("mockOne", "error", err)
		return nil, err
	}

	c.log.Debug("3")

	return mockUpload, nil
}
