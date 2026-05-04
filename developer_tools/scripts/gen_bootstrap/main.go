package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/socialsecurity"
	"github.com/SUNET/vc/pkg/vcclient"

	"gopkg.in/yaml.v2"
)

// InputFile is the top-level YAML structure.
type InputFile struct {
	Defaults PersonDefaults     `yaml:"defaults"`
	Persons  map[string]*Person `yaml:"persons"`
}

// PersonDefaults hold values shared across all persons.
type PersonDefaults struct {
	BirthPlace       string   `yaml:"birth_place"`
	Nationality      []string `yaml:"nationality"`
	IssuingAuthority string   `yaml:"issuing_authority"`
	IssuingCountry   string   `yaml:"issuing_country"`
	ExpiryDate       string   `yaml:"expiry_date"`
}

// Person describes one test person.
type Person struct {
	GivenName  string `yaml:"given_name"`
	FamilyName string `yaml:"family_name"`
	BirthDate  string `yaml:"birth_date"`

	PID  *PIDFields  `yaml:"pid,omitempty"`
	EHIC *EHICFields `yaml:"ehic,omitempty"`
	PDA1 *PDA1Fields `yaml:"pda1,omitempty"`
}

// PIDFields are the extra per-person fields used in PID-1-5, PID-1-8 and eduID credentials.
type PIDFields struct {
	BirthFamilyName              string `yaml:"birth_family_name"`
	BirthGivenName               string `yaml:"birth_given_name"`
	Sex                          string `yaml:"sex"`
	EmailAddress                 string `yaml:"email_address"`
	MobilePhoneNumber            string `yaml:"mobile_phone_number"`
	ResidentAddress              string `yaml:"resident_address"`
	ResidentStreetAddress        string `yaml:"resident_street_address"`
	ResidentHouseNumber          string `yaml:"resident_house_number"`
	ResidentPostalCode           string `yaml:"resident_postal_code"`
	ResidentCity                 string `yaml:"resident_city"`
	ResidentState                string `yaml:"resident_state"`
	ResidentCountry              string `yaml:"resident_country"`
	DocumentNumber               string `yaml:"document_number"`
	PersonalAdministrativeNumber string `yaml:"personal_administrative_number"`
	IssuanceDate                 string `yaml:"issuance_date"`
	IssuingJurisdiction          string `yaml:"issuing_jurisdiction"`
}

// EHICFields are the per-person fields for EHIC credentials.
type EHICFields struct {
	PersonalAdministrativeNumber string `yaml:"personal_administrative_number"`
	DocumentNumber               string `yaml:"document_number"`
	IssuingCountry               string `yaml:"issuing_country"`
	InstitutionID                string `yaml:"institution_id"`
	DateOfIssuance               string `yaml:"date_of_issuance"`
	DateOfExpiry                 string `yaml:"date_of_expiry"`
}

// PDA1Fields are the per-person fields for PDA1 credentials.
type PDA1Fields struct {
	PersonalAdministrativeNumber string           `yaml:"personal_administrative_number"`
	DocumentNumber               string           `yaml:"document_number"`
	DateOfIssuance               string           `yaml:"date_of_issuance"`
	DateOfExpiry                 string           `yaml:"date_of_expiry"`
	StatusConfirmation           string           `yaml:"status_confirmation"`
	Employer                     *PDA1Employer    `yaml:"employer,omitempty"`
	WorkAddress                  *PDA1WorkAddress `yaml:"work_address,omitempty"`
}

// PDA1Employer describes the employer for PDA1.
type PDA1Employer struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Country string `yaml:"country"`
}

// PDA1WorkAddress describes the work address for PDA1.
type PDA1WorkAddress struct {
	Formatted     string `yaml:"formatted"`
	StreetAddress string `yaml:"street_address"`
	HouseNumber   string `yaml:"house_number"`
	PostalCode    string `yaml:"postal_code"`
	Locality      string `yaml:"locality"`
	Region        string `yaml:"region"`
	Country       string `yaml:"country"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: gen_bootstrap <input.yaml> <output-dir>\n")
		os.Exit(1)
	}
	inputPath := os.Args[1]
	outputDir := os.Args[2]

	data, err := os.ReadFile(filepath.Clean(inputPath))
	if err != nil {
		fatal("read input: %v", err)
	}

	var input InputFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&input); err != nil { //#nosec G709 -- developer CLI tool, input is trusted
		fatal("parse yaml: %v", err)
	}

	cleanOutputDir := filepath.Clean(outputDir)
	if err := os.MkdirAll(cleanOutputDir, 0750); err != nil {
		fatal("create output dir: %v", err)
	}

	// Sorted person IDs for deterministic output.
	pids := sortedKeys(input.Persons)

	writeJSON(outputDir, "pid-1-5.json", genPID15(pids, &input))
	writeJSON(outputDir, "pid-1-8.json", genPID18(pids, &input))
	writeJSON(outputDir, "eduid.json", genEduID(pids, &input))
	writeJSON(outputDir, "ehic.json", genEHIC(pids, &input))
	writeJSON(outputDir, "pda1.json", genPDA1(pids, &input))
	writeJSON(outputDir, "elm.json", genELM(pids, &input))
	writeJSON(outputDir, "diploma.json", genDiploma(pids, &input))
	writeJSON(outputDir, "microcredential.json", genMicroCredential(pids, &input))

	fmt.Printf("Generated %d credential files for %d persons in %s\n", 8, len(pids), outputDir)
}

// --- PID ARF 1.5 ---

func genPID15(pids []string, input *InputFile) map[string]*vcclient.UploadRequest {
	result := make(map[string]*vcclient.UploadRequest, len(pids))
	for _, pid := range pids {
		p := input.Persons[pid]

		aspid := fmt.Sprintf("authentic_source_person_id_%s", pid)
		dd := makePIDDocumentData(p, aspid, &input.Defaults)
		dd["arf"] = "1.5"

		result[pid] = &vcclient.UploadRequest{
			DocumentData: dd,
			Meta: &model.MetaData{
				AuthenticSource: "PID_Provider:00001",
				Scope:           "pid_1_5",
				DocumentID:      fmt.Sprintf("document_id_pid_arf_1_5_%s", pid),
			},
			IdentityMappingIDs: []string{fmt.Sprintf("authentic_source_person_id_%s", pid)},
		}
	}
	return result
}

// --- PID ARF 1.8 ---

func genPID18(pids []string, input *InputFile) map[string]*vcclient.UploadRequest {
	result := make(map[string]*vcclient.UploadRequest, len(pids))
	now := time.Now()
	for _, pid := range pids {
		p := input.Persons[pid]

		age := calcAge(p.BirthDate)

		pidExt := p.PID
		if pidExt == nil {
			pidExt = &PIDFields{}
		}

		dd := map[string]any{
			"given_name":  p.GivenName,
			"family_name": p.FamilyName,
			"birthdate":   p.BirthDate,
			"place_of_birth": map[string]any{
				"locality": input.Defaults.BirthPlace,
				"region":   or_(pidExt.ResidentState, "Stockholm"),
				"country":  firstOr(input.Defaults.Nationality, "SE"),
			},
			"issuing_authority":              input.Defaults.IssuingAuthority,
			"issuing_country":                input.Defaults.IssuingCountry,
			"nationalities":                  input.Defaults.Nationality,
			"issuing_jurisdiction":           or_(pidExt.IssuingJurisdiction, "SUNET"),
			"date_of_expiry":                 now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
			"expiry_date":                    now.Add(365 * 24 * time.Hour).Format("2006-01-02"),
			"date_of_issuance":               now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
			"arf":                            "1.8",
			"document_number":                or_(pidExt.DocumentNumber, fmt.Sprintf("doc-pid18-%s", pid)),
			"personal_administrative_number": or_(pidExt.PersonalAdministrativeNumber, fmt.Sprintf("pan-%s", pid)),
			"picture":                        minPNG,
			"birth_family_name":              or_(pidExt.BirthFamilyName, p.FamilyName),
			"birth_given_name":               or_(pidExt.BirthGivenName, p.GivenName),
			"sex":                            or_(pidExt.Sex, "0"),
			"email":                          or_(pidExt.EmailAddress, fmt.Sprintf("%s@example.com", toLower(p.FamilyName))),
			"phone_number":                   or_(pidExt.MobilePhoneNumber, "+46700000000"),
			"address": map[string]any{
				"locality":       or_(pidExt.ResidentCity, "Stockholm"),
				"country":        input.Defaults.IssuingCountry,
				"formatted":      or_(pidExt.ResidentAddress, "Tulegatan 11, Stockholm"),
				"postal_code":    or_(pidExt.ResidentPostalCode, "11353"),
				"house_number":   or_(pidExt.ResidentHouseNumber, "11"),
				"street_address": or_(pidExt.ResidentStreetAddress, "Tulegatan"),
				"region":         or_(pidExt.ResidentState, "Stockholm"),
			},
			"age_equal_or_over": map[string]any{
				"14": age >= 14,
				"16": age >= 16,
				"18": age >= 18,
				"21": age >= 21,
				"65": age >= 65,
			},
			"age_in_years":   age,
			"age_birth_year": parseBirthYear(p.BirthDate),
		}

		result[pid] = &vcclient.UploadRequest{
			DocumentData: dd,
			Meta: &model.MetaData{
				AuthenticSource: "PID_Provider:00001",
				Scope:           "pid_1_8",
				DocumentID:      fmt.Sprintf("document_id_pid_arf_1_8_%s", pid),
			},
			IdentityMappingIDs: []string{fmt.Sprintf("authentic_source_person_id_%s", pid)},
		}
	}
	return result
}

// --- EduID ---

func genEduID(pids []string, input *InputFile) map[string]*vcclient.UploadRequest {
	result := make(map[string]*vcclient.UploadRequest, len(pids))
	now := time.Now()
	for _, pid := range pids {
		p := input.Persons[pid]

		age := calcAge(p.BirthDate)

		pidExt := p.PID
		if pidExt == nil {
			pidExt = &PIDFields{}
		}

		dd := map[string]any{
			"given_name":  p.GivenName,
			"family_name": p.FamilyName,
			"birthdate":   p.BirthDate,
			"place_of_birth": map[string]any{
				"locality": input.Defaults.BirthPlace,
				"region":   or_(pidExt.ResidentState, "Stockholm"),
				"country":  firstOr(input.Defaults.Nationality, "SE"),
			},
			"issuing_authority":              input.Defaults.IssuingAuthority,
			"issuing_country":                input.Defaults.IssuingCountry,
			"nationalities":                  input.Defaults.Nationality,
			"issuing_jurisdiction":           or_(pidExt.IssuingJurisdiction, "SUNET"),
			"date_of_expiry":                 now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
			"expiry_date":                    now.Add(365 * 24 * time.Hour).Format("2006-01-02"),
			"date_of_issuance":               now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
			"document_number":                or_(pidExt.DocumentNumber, fmt.Sprintf("doc-eduid-%s", pid)),
			"personal_administrative_number": or_(pidExt.PersonalAdministrativeNumber, fmt.Sprintf("pan-%s", pid)),
			"picture":                        minPNG,
			"birth_family_name":              or_(pidExt.BirthFamilyName, p.FamilyName),
			"birth_given_name":               or_(pidExt.BirthGivenName, p.GivenName),
			"sex":                            or_(pidExt.Sex, "0"),
			"email":                          or_(pidExt.EmailAddress, fmt.Sprintf("%s@example.com", toLower(p.FamilyName))),
			"phone_number":                   or_(pidExt.MobilePhoneNumber, "+46700000000"),
			"address": map[string]any{
				"locality":       or_(pidExt.ResidentCity, "Stockholm"),
				"country":        input.Defaults.IssuingCountry,
				"formatted":      or_(pidExt.ResidentAddress, "Tulegatan 11, Stockholm"),
				"postal_code":    or_(pidExt.ResidentPostalCode, "11353"),
				"house_number":   or_(pidExt.ResidentHouseNumber, "11"),
				"street_address": or_(pidExt.ResidentStreetAddress, "Tulegatan"),
				"region":         or_(pidExt.ResidentState, "Stockholm"),
			},
			"age_equal_or_over": map[string]any{
				"14": age >= 14,
				"16": age >= 16,
				"18": age >= 18,
				"21": age >= 21,
				"65": age >= 65,
			},
			"age_in_years":   age,
			"age_birth_year": parseBirthYear(p.BirthDate),
		}

		result[pid] = &vcclient.UploadRequest{
			DocumentData: dd,
			Meta: &model.MetaData{
				AuthenticSource: "eduID_Provider:00001",
				Scope:           "eduid",
				DocumentID:      fmt.Sprintf("document_id_eduid_%s", pid),
			},
			IdentityMappingIDs: []string{fmt.Sprintf("authentic_source_person_id_%s", pid)},
		}
	}
	return result
}

// --- EHIC ---

func genEHIC(pids []string, input *InputFile) map[string]*vcclient.UploadRequest {
	result := make(map[string]*vcclient.UploadRequest, len(pids))
	now := time.Now()
	for _, pid := range pids {
		p := input.Persons[pid]

		if p.EHIC == nil {
			continue
		}
		e := p.EHIC

		doc := &socialsecurity.EHICDocument{
			PersonalAdministrativeNumber: e.PersonalAdministrativeNumber,
			IssuingAuthority: socialsecurity.IssuingAuthority{
				ID:   or_(e.InstitutionID, "CLEISS"),
				Name: input.Defaults.IssuingAuthority,
			},
			IssuingCountry: or_(e.IssuingCountry, "FR"),
			DateOfExpiry:   e.DateOfExpiry,
			DateOfIssuance: e.DateOfIssuance,
			DocumentNumber: e.DocumentNumber,
			StartingDate:   now.Format("2006-01-02"),
			EndingDate:     now.AddDate(1, 0, 0).Format("2006-01-02"),
			AuthenticSource: socialsecurity.AuthenticSource{
				ID:   or_(e.InstitutionID, "CLEISS"),
				Name: input.Defaults.IssuingAuthority,
			},
		}

		dd, err := doc.Marshal()
		if err != nil {
			fatal("ehic marshal %s: %v", pid, err)
		}

		result[pid] = &vcclient.UploadRequest{
			DocumentData: dd,
			Meta: &model.MetaData{
				AuthenticSource: "EHIC:00001",
				Scope:           "ehic",
				DocumentID:      fmt.Sprintf("document_id_ehic_%s", pid),
			},
			IdentityMappingIDs: []string{fmt.Sprintf("authentic_source_person_id_%s", pid)},
		}
	}
	return result
}

// --- PDA1 ---

func genPDA1(pids []string, input *InputFile) map[string]*vcclient.UploadRequest {
	result := make(map[string]*vcclient.UploadRequest, len(pids))
	now := time.Now()
	for _, pid := range pids {
		p := input.Persons[pid]

		if p.PDA1 == nil {
			continue
		}
		d := p.PDA1

		employer := socialsecurity.Employer{ID: "01", Name: "SUNET", Country: "SE"}
		if d.Employer != nil {
			employer = socialsecurity.Employer{ID: d.Employer.ID, Name: d.Employer.Name, Country: d.Employer.Country}
		}

		wa := socialsecurity.WorkAddress{
			Formatted:      "Tulegatan 11, Stockholm",
			Street_address: "Tulegatan",
			House_number:   "11",
			Postal_code:    "11353",
			Locality:       "Stockholm",
			Region:         "Stockholm",
			Country:        "SE",
		}
		if d.WorkAddress != nil {
			wa = socialsecurity.WorkAddress{
				Formatted:      d.WorkAddress.Formatted,
				Street_address: d.WorkAddress.StreetAddress,
				House_number:   d.WorkAddress.HouseNumber,
				Postal_code:    d.WorkAddress.PostalCode,
				Locality:       d.WorkAddress.Locality,
				Region:         d.WorkAddress.Region,
				Country:        d.WorkAddress.Country,
			}
		}

		doc := &socialsecurity.PDA1Document{
			PersonalAdministrativeNumber: d.PersonalAdministrativeNumber,
			Employer:                     employer,
			WorkAddress:                  wa,
			IssuingAuthority: socialsecurity.IssuingAuthority{
				ID:   "01",
				Name: input.Defaults.IssuingAuthority,
			},
			LegislationCountry: "EU",
			StatusConfirmation: or_(d.StatusConfirmation, "02"),
			IssuingCountry:     "EU",
			DateOfExpiry:       d.DateOfExpiry,
			DateOfIssuance:     d.DateOfIssuance,
			DocumentNumber:     d.DocumentNumber,
			StartingDate:       now.Format("2006-01-02"),
			EndingDate:         now.AddDate(1, 0, 0).Format("2006-01-02"),
			AuthenticSource: socialsecurity.AuthenticSource{
				ID:   fmt.Sprintf("pda1-as-%s", pid),
				Name: input.Defaults.IssuingAuthority,
			},
		}

		dd, err := doc.Marshal()
		if err != nil {
			fatal("pda1 marshal %s: %v", pid, err)
		}

		result[pid] = &vcclient.UploadRequest{
			DocumentData: dd,
			Meta: &model.MetaData{
				AuthenticSource: "PDA1:00001",
				Scope:           "pda1",
				DocumentID:      fmt.Sprintf("document_id_pda1_%s", pid),
			},
			IdentityMappingIDs: []string{fmt.Sprintf("authentic_source_person_id_%s", pid)},
		}
	}
	return result
}

// --- ELM ---

func genELM(pids []string, input *InputFile) map[string]*model.CompleteDocument {
	exampleData := loadExampleJSON("standards/elm_3_2.json")
	result := make(map[string]*model.CompleteDocument, len(pids))
	for _, pid := range pids {

		result[pid] = &model.CompleteDocument{
			DocumentData: exampleData,
			Meta: &model.MetaData{
				AuthenticSource: "ELM:00001",
				Scope:           "elm",
				DocumentID:      fmt.Sprintf("document_id_elm_%s", pid),
			},
			IdentityMappingIDs: []string{fmt.Sprintf("authentic_source_person_id_%s", pid)},
		}
	}
	return result
}

// --- Diploma ---

func genDiploma(pids []string, input *InputFile) map[string]*vcclient.UploadRequest {
	exampleData := loadExampleJSON("standards/education_credential/diploma/HE-diploma-9ad88a95-2f9a-4a1d-9e08-a61e213a3eac-degreeHBO-M.xml.json")
	result := make(map[string]*vcclient.UploadRequest, len(pids))
	for _, pid := range pids {

		result[pid] = &vcclient.UploadRequest{
			DocumentData: exampleData,
			Meta: &model.MetaData{
				AuthenticSource: "DIPLOMA:00001",
				Scope:           "diploma",
				DocumentID:      fmt.Sprintf("document_id_diploma_%s", pid),
			},
			IdentityMappingIDs: []string{fmt.Sprintf("authentic_source_person_id_%s", pid)},
		}
	}
	return result
}

// --- MicroCredential ---

func genMicroCredential(pids []string, input *InputFile) map[string]*vcclient.UploadRequest {
	exampleData := loadExampleJSON("standards/education_credential/micro_credential/uvh_fvhz_microcredential_full.json")
	result := make(map[string]*vcclient.UploadRequest, len(pids))
	for _, pid := range pids {

		result[pid] = &vcclient.UploadRequest{
			DocumentData: exampleData,
			Meta: &model.MetaData{
				AuthenticSource: "MICROCREDENTIAL:00001",
				Scope:           "microcredential",
				DocumentID:      fmt.Sprintf("document_id_microcredential_%s", pid),
			},
			IdentityMappingIDs: []string{fmt.Sprintf("authentic_source_person_id_%s", pid)},
		}
	}
	return result
}

// --- Helpers ---

const minPNG = "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAFElEQVQYV2P8z8DwHwYGBgZGMAEADigBCCGZkB0AAAAASUVORK5CYII="

func makePIDDocumentData(p *Person, authenticSourcePersonID string, defaults *PersonDefaults) map[string]any {
	age := calcAge(p.BirthDate)

	pidExt := p.PID
	if pidExt == nil {
		pidExt = &PIDFields{}
	}

	return map[string]any{
		"given_name":                     p.GivenName,
		"family_name":                    p.FamilyName,
		"birthdate":                      p.BirthDate,
		"birth_place":                    defaults.BirthPlace,
		"age_birth_year":                 parseBirthYear(p.BirthDate),
		"age_in_years":                   age,
		"age_over_14":                    age >= 14,
		"age_over_16":                    age >= 16,
		"age_over_18":                    age >= 18,
		"age_over_21":                    age >= 21,
		"age_over_65":                    age >= 65,
		"birth_family_name":              or_(pidExt.BirthFamilyName, p.FamilyName),
		"birth_given_name":               or_(pidExt.BirthGivenName, p.GivenName),
		"sex":                            or_(pidExt.Sex, "0"),
		"nationality":                    defaults.Nationality,
		"issuing_country":                defaults.IssuingCountry,
		"issuing_authority":              defaults.IssuingAuthority,
		"issuing_jurisdiction":           or_(pidExt.IssuingJurisdiction, "Stockholm"),
		"document_number":                or_(pidExt.DocumentNumber, fmt.Sprintf("doc-pid15-%s-%s", toLower(p.FamilyName), authenticSourcePersonID)),
		"personal_administrative_number": or_(pidExt.PersonalAdministrativeNumber, fmt.Sprintf("pan-%s", authenticSourcePersonID)),
		"issuance_date":                  or_(pidExt.IssuanceDate, "2024-01-01"),
		"expiry_date":                    defaults.ExpiryDate,
		"picture":                        minPNG,
		"email_address":                  or_(pidExt.EmailAddress, fmt.Sprintf("%s@example.com", toLower(p.FamilyName))),
		"mobile_phone_number":            or_(pidExt.MobilePhoneNumber, "+46700000000"),
		"resident_address":               or_(pidExt.ResidentAddress, "Tulegatan 11, Stockholm"),
		"resident_street_address":        or_(pidExt.ResidentStreetAddress, "Tulegatan"),
		"resident_house_number":          or_(pidExt.ResidentHouseNumber, "11"),
		"resident_postal_code":           or_(pidExt.ResidentPostalCode, "11353"),
		"resident_city":                  or_(pidExt.ResidentCity, "Stockholm"),
		"resident_state":                 or_(pidExt.ResidentState, "Stockholm"),
		"resident_country":               or_(pidExt.ResidentCountry, "SE"),
	}
}

func calcAge(birthDate string) int {
	bd, err := time.Parse("2006-01-02", birthDate)
	if err != nil {
		return 0
	}
	now := time.Now()
	age := now.Year() - bd.Year()
	if now.YearDay() < bd.YearDay() {
		age--
	}
	return age
}

func parseBirthYear(birthDate string) int {
	bd, err := time.Parse("2006-01-02", birthDate)
	if err != nil {
		return 0
	}
	return bd.Year()
}

func sortedKeys(m map[string]*Person) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, _ := strconv.Atoi(keys[i])
		b, _ := strconv.Atoi(keys[j])
		return a < b
	})
	return keys
}

func or_(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}

func firstOr(vals []string, fallback string) string {
	if len(vals) > 0 {
		return vals[0]
	}
	return fallback
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func writeJSON(dir, filename string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal("marshal %s: %v", filename, err)
	}
	// Append newline for consistent file formatting
	b = append(b, '\n')
	path := filepath.Join(filepath.Clean(dir), filepath.Clean(filename))
	if err := os.WriteFile(path, b, 0600); err != nil {
		fatal("write %s: %v", path, err)
	}
	fmt.Printf("  wrote %s (%d bytes)\n", filename, len(b))
}

func loadExampleJSON(relativePath string) map[string]any {
	b, err := os.ReadFile(filepath.Clean(relativePath))
	if err != nil {
		fatal("read example %s: %v", relativePath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		fatal("parse example %s: %v", relativePath, err)
	}
	return doc
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen_bootstrap: "+format+"\n", args...)
	os.Exit(1)
}
