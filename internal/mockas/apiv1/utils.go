package apiv1

import (
	"context"
	"time"

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
	Meta                *model.MetaData        `json:"meta" validate:"required"`
	Identities          []model.Identity       `json:"identities,omitempty" validate:"required,dive"`
	DocumentDisplay     *model.DocumentDisplay `json:"document_display,omitempty" validate:"required"`
	DocumentData        map[string]any         `json:"document_data" validate:"required"`
	DocumentDataVersion string                 `json:"document_data_version,omitempty" validate:"required,semver"`
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
		VCT:             data.VCT,
		DocumentID:      data.DocumentID,
		DocumentVersion: "1.0.0",
		RealData:        false,
		Collect: &model.Collect{
			ID:         data.CollectID,
			ValidUntil: time.Now().Add(10 * 24 * time.Hour).Unix(),
		},
		CredentialValidFrom: gofakeit.Date().Unix(),
		CredentialValidTo:   gofakeit.Date().Unix(),
		Revocation: &model.Revocation{
			ID:      gofakeit.UUID(),
			Revoked: false,
			Reference: model.RevocationReference{
				AuthenticSource: data.AuthenticSource,
				VCT:             data.VCT,
				DocumentID:      data.DocumentID,
			},
		},
	}

	identities := []model.Identity{
		{
			AuthenticSourcePersonID: data.AuthenticSourcePersonID,
			Schema: &model.IdentitySchema{
				Name:    data.IdentitySchemaName,
				Version: "1.0.0",
			},
			FamilyName: data.FamilyName,
			GivenName:  data.GivenName,
			BirthDate:  data.BirthDate,
		},
	}

	documentDisplay := &model.DocumentDisplay{
		Version: "1.0.0",
		Type:    data.VCT,
		DescriptionStructured: map[string]any{
			"en": "issuer",
			"sv": "utfärdare",
		},
	}

	mockUpload := &uploadMock{
		Meta:            meta,
		Identities:      identities,
		DocumentDisplay: documentDisplay,
	}

	var err error
	switch data.VCT {
	case model.CredentialTypeUrnEudiPda11:
		mockUpload.DocumentData, err = c.PDA1.random(ctx, person)
		if err != nil {
			return nil, err
		}
		mockUpload.Meta.DocumentDataValidationRef = "file://../../standards/schema_pda1.json"
	case model.CredentialTypeUrnEudiEhic1:
		mockUpload.DocumentData, err = c.EHIC.random(ctx, person)
		if err != nil {
			return nil, err
		}
		mockUpload.Meta.DocumentDataValidationRef = "file://../../standards/schema_ehic.json"
	case model.CredentialTypeUrnEudiPid1:
		mockUpload.DocumentData, err = c.PID.random(ctx, person)
		if err != nil {
			return nil, err
		}

	case model.CredentialTypeUrnEudiElm1:
		mockUpload.DocumentData, err = c.ELM.random(ctx, person)
		if err != nil {
			return nil, err
		}
	default:
		return nil, helpers.ErrNoKnownVCT
	}

	mockUpload.DocumentDataVersion = "1.0.0"

	c.log.Debug("2")
	if err := helpers.CheckSimple(mockUpload); err != nil {
		c.log.Debug("mockOne", "error", err)
		return nil, err
	}

	c.log.Debug("3")

	return mockUpload, nil
}
