package bootstrapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/brianvoe/gofakeit/v7"
)

type pidClient struct {
	client         *Client
	documents      map[string]*vcclient.UploadRequest
	credentialType string
	pidUsers       map[string]*vcclient.AddPIDRequest
}

func NewPIDClient(ctx context.Context, client *Client) (*pidClient, error) {
	pidClient := &pidClient{
		client:         client,
		documents:      map[string]*vcclient.UploadRequest{},
		credentialType: "pid-1-5",
	}

	return pidClient, nil
}

func (c *pidClient) readPidUserFile(sourceFilePath string) error {
	f, err := os.Open(filepath.Clean(sourceFilePath))
	if err != nil {
		return fmt.Errorf("open pid user file: %w", err)
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&c.pidUsers); err != nil {
		return fmt.Errorf("decode pid user file: %w", err)
	}

	return nil
}

func (c *pidClient) makeSourceData(sourceFilePath string) error {
	if err := c.readPidUserFile(sourceFilePath); err != nil {
		return fmt.Errorf("read pid user file: %w", err)
	}

	for pidNumber, id := range c.pidUsers {
		c.documents[pidNumber] = &vcclient.UploadRequest{}

		// Parse birthdate to calculate age-related fields
		birthDate, _ := time.Parse("2006-01-02", id.Identity.BirthDate)
		now := time.Now()
		age := now.Year() - birthDate.Year()
		if now.YearDay() < birthDate.YearDay() {
			age--
		}

		// Use identity values if provided, otherwise generate fake data or calculate
		birthPlace := id.Identity.BirthPlace
		if birthPlace == "" {
			birthPlace = gofakeit.City()
		}

		issuingAuthority := id.Identity.IssuingAuthority
		if issuingAuthority == "" {
			issuingAuthority = gofakeit.Company()
		}

		expiryDate := id.Identity.ExpiryDate
		if expiryDate == "" {
			expiryDate = gofakeit.FutureDate().Format("2006-01-02")
		}

		authenticSourcePersonID := id.Identity.AuthenticSourcePersonID
		if authenticSourcePersonID == "" {
			authenticSourcePersonID = gofakeit.UUID()
		}

		// Age fields - use identity values if provided, otherwise calculate
		ageBirthYear := id.Identity.AgeBirthYear
		if ageBirthYear == 0 {
			ageBirthYear = birthDate.Year()
		}

		ageInYears := id.Identity.AgeInYears
		if ageInYears == 0 {
			ageInYears = age
		}

		// Age over flags - use identity values if provided, otherwise calculate
		var ageOver14 any = id.Identity.AgeOver14
		if id.Identity.AgeOver14 == "" {
			ageOver14 = age >= 14
		}

		ageOver16 := id.Identity.AgeOver16
		if !ageOver16 && age >= 16 {
			ageOver16 = true
		}

		ageOver18 := id.Identity.AgeOver18
		if !ageOver18 && age >= 18 {
			ageOver18 = true
		}

		ageOver21 := id.Identity.AgeOver21
		if !ageOver21 && age >= 21 {
			ageOver21 = true
		}

		ageOver65 := id.Identity.AgeOver65
		if !ageOver65 && age >= 65 {
			ageOver65 = true
		}

		birthFamilyName := id.Identity.BirthFamilyName
		if birthFamilyName == "" {
			birthFamilyName = gofakeit.LastName()
		}

		birthGivenName := id.Identity.BirthGivenName
		if birthGivenName == "" {
			birthGivenName = gofakeit.FirstName()
		}

		sex := id.Identity.Sex
		if sex == "" {
			sex = strconv.Itoa(gofakeit.RandomInt([]int{0, 1, 2, 9}))
		}

		var nationality any = id.Identity.Nationality
		if len(id.Identity.Nationality) == 0 {
			nationality = gofakeit.CountryAbr()
		}

		issuingJurisdiction := id.Identity.IssuingJurisdiction
		if issuingJurisdiction == "" {
			issuingJurisdiction = gofakeit.State()
		}

		documentNumber := id.Identity.DocumentNumber
		if documentNumber == "" {
			documentNumber = gofakeit.UUID()
		}

		personalAdministrativeNumber := id.Identity.PersonalAdministrativeNumber
		if personalAdministrativeNumber == "" {
			personalAdministrativeNumber = gofakeit.SSN()
		}

		issuanceDate := id.Identity.IssuanceDate
		if issuanceDate == "" {
			issuanceDate = gofakeit.Date().Format("2006-01-02")
		}

		picture := id.Identity.Picture
		if picture == "" {
			picture = "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAFElEQVQYV2P8z8DwHwYGBgZGMAEADigBCCGZkB0AAAAASUVORK5CYII="
		}

		emailAddress := id.Identity.EmailAddress
		if emailAddress == "" {
			emailAddress = gofakeit.Email()
		}

		mobilePhoneNumber := id.Identity.MobilePhoneNumber
		if mobilePhoneNumber == "" {
			mobilePhoneNumber = gofakeit.Phone()
		}

		residentAddress := id.Identity.ResidentAddress
		if residentAddress == "" {
			residentAddress = fmt.Sprintf("%s, %s %s", gofakeit.Street(), gofakeit.City(), gofakeit.Zip())
		}

		residentStreetAddress := id.Identity.ResidentStreetAddress
		if residentStreetAddress == "" {
			residentStreetAddress = gofakeit.Street()
		}

		residentHouseNumber := id.Identity.ResidentHouseNumber
		if residentHouseNumber == "" {
			residentHouseNumber = gofakeit.StreetNumber()
		}

		residentPostalCode := id.Identity.ResidentPostalCode
		if residentPostalCode == "" {
			residentPostalCode = gofakeit.Zip()
		}

		residentCity := id.Identity.ResidentCity
		if residentCity == "" {
			residentCity = gofakeit.City()
		}

		residentState := id.Identity.ResidentState
		if residentState == "" {
			residentState = gofakeit.State()
		}

		residentCountry := id.Identity.ResidentCountry
		if residentCountry == "" {
			residentCountry = gofakeit.CountryAbr()
		}

		trustAnchor := id.Identity.TrustAnchor
		if trustAnchor == "" {
			trustAnchor = "https://" + gofakeit.DomainName()
		}

		c.documents[pidNumber].DocumentData = map[string]any{
			"given_name":                     id.Identity.GivenName,
			"family_name":                    id.Identity.FamilyName,
			"birthdate":                      id.Identity.BirthDate,
			"birth_place":                    birthPlace,
			"age_birth_year":                 ageBirthYear,
			"age_in_years":                   ageInYears,
			"age_over_14":                    ageOver14,
			"age_over_16":                    ageOver16,
			"age_over_18":                    ageOver18,
			"age_over_21":                    ageOver21,
			"age_over_65":                    ageOver65,
			"birth_family_name":              birthFamilyName,
			"birth_given_name":               birthGivenName,
			"sex":                            sex,
			"nationality":                    nationality,
			"issuing_country":                id.Identity.IssuingCountry,
			"issuing_authority":              issuingAuthority,
			"issuing_jurisdiction":           issuingJurisdiction,
			"document_number":                documentNumber,
			"personal_administrative_number": personalAdministrativeNumber,
			"issuance_date":                  issuanceDate,
			"expiry_date":                    expiryDate,
			"picture":                        picture,
			"email_address":                  emailAddress,
			"mobile_phone_number":            mobilePhoneNumber,
			"resident_address":               residentAddress,
			"resident_street_address":        residentStreetAddress,
			"resident_house_number":          residentHouseNumber,
			"resident_postal_code":           residentPostalCode,
			"resident_city":                  residentCity,
			"resident_state":                 residentState,
			"resident_country":               residentCountry,
			"authentic_source_person_id":     authenticSourcePersonID,
			"trust_anchor":                   trustAnchor,
			"arf":                            "1.5",
		}

		c.documents[pidNumber].Meta = &model.MetaData{
			AuthenticSource: "PID_Provider:00001",
			DocumentVersion: "1.0.0",
			VCT:             model.CredentialTypeUrnEudiPidARF151,
			Scope:           "pid_1_5",
			DocumentID:      fmt.Sprintf("document_id_pid_arf_1_5_%s", pidNumber),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_pid_%s", pidNumber),
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
					"description": "Personal Identification Document",
				},
				"sv": map[string]any{
					"beskrivning": "Personligt identifikationsdokument",
				},
			},
		}

		c.documents[pidNumber].Identities = []model.Identity{*id.Identity}

		c.documents[pidNumber].DocumentDataVersion = "1.0.0"
	}

	return nil
}

func (c *pidClient) save2Disk() error {
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
