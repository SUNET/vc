package main

import "encoding/json"

// EHICDocument is the EHIC model
type EHICDocument struct {
	PersonalAdministrativeNumber string           `json:"personal_administrative_number" bson:"personalAdministrativeNumber" validate:"required,min=4,max=50"`
	IssuingAuthority             IssuingAuthority `json:"issuing_authority" bson:"issuingAuthority" validate:"required"`
	IssuingCountry               string           `json:"issuing_country" bson:"issuingCountry" validate:"required,iso3166_1_alpha2"`
	DateOfExpiry                 string           `json:"date_of_expiry" bson:"dateOfExpiry" validate:"required"`
	DateOfIssuance               string           `json:"date_of_issuance" bson:"dateOfIssuance" validate:"required"`
	DocumentNumber               string           `json:"document_number" bson:"documentNumber" validate:"required,min=4,max=50"`
	AuthenticSource              AuthenticSource  `json:"authentic_source" bson:"authenticSource" validate:"required"`
	EndingDate                   string           `json:"ending_date" bson:"endingDate" validate:"required"`
	StartingDate                 string           `json:"starting_date" bson:"startingDate" validate:"required"`
}

// Marshal marshals the document to a map
func (d *EHICDocument) Marshal() (map[string]any, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}

	var doc map[string]any
	err = json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}
