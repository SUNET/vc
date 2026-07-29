package main

import "encoding/json"

// PDA1Document model for PDA1
type PDA1Document struct {
	PersonalAdministrativeNumber string           `json:"personal_administrative_number" bson:"personal_administrative_number" validate:"required,min=4,max=50"`
	Employer                     Employer         `json:"employer" bson:"employer" validate:"required"`
	WorkAddress                  WorkAddress      `json:"work_address" bson:"work_address" validate:"required"`
	IssuingAuthority             IssuingAuthority `json:"issuing_authority" bson:"issuing_authority" validate:"required,iso3166_1_alpha2"`
	LegislationCountry           string           `json:"legislation_country" bson:"legislation_country" validate:"required,iso3166_1_alpha2"`
	StatusConfirmation           string           `json:"status_confirmation" bson:"status_confirmation" validate:"required,oneof=02 03 04 05 06 07 08 09 10 11 12"`
	IssuingCountry               string           `json:"issuing_country" bson:"issuing_country" validate:"required,iso3166_1_alpha2"`
	DateOfExpiry                 string           `json:"date_of_expiry" bson:"date_of_expiry" validate:"required"`
	DateOfIssuance               string           `json:"date_of_issuance" bson:"date_of_issuance" validate:"required"`
	DocumentNumber               string           `json:"document_number" bson:"document_number" validate:"required,min=4,max=50"`
	AuthenticSource              AuthenticSource  `json:"authentic_source" bson:"authentic_source" validate:"required"`
	EndingDate                   string           `json:"ending_date" bson:"endingDate" validate:"required"`
	StartingDate                 string           `json:"starting_date" bson:"startingDate" validate:"required"`
}

// Marshal marshals the document to a map
func (d *PDA1Document) Marshal() (map[string]any, error) {
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

type Employer struct {
	ID      string `json:"id" bson:"id" validate:"required,min=1,max=20"`
	Name    string `json:"name" bson:"name" validate:"required,min=1,max=100"`
	Country string `json:"country" bson:"country" validate:"required,iso3166_1_alpha2"`
}

type WorkAddress struct {
	Formatted      string `json:"formatted" bson:"formatted" validate:"omitempty,min=2,max=512"`
	Street_address string `json:"street_address" bson:"street_address" validate:"omitempty,min=1,max=100"`
	House_number   string `json:"house_number" bson:"house_number" validate:"omitempty,min=1,max=20"`
	Postal_code    string `json:"postal_code" bson:"postal_code" validate:"omitempty,min=1,max=20"`
	Locality       string `json:"locality" bson:"locality" validate:"required,min=1,max=100"`
	Region         string `json:"region" bson:"region" validate:"omitempty,min=1,max=100"`
	Country        string `json:"country" bson:"country" validate:"required,iso3166_1_alpha2"`
}
