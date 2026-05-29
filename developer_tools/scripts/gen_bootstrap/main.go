package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"

	"gopkg.in/yaml.v2"
)

// genericFacePNGBytes is a placeholder head-and-shoulders avatar used as the
// "picture" claim for every bootstrapped test person. Not an actual portrait
// of anyone — just a recognizable face so the credential card has something
// to render in its photo frame.
//
//go:embed generic_face.png
var genericFacePNGBytes []byte

// genericFacePNG is genericFacePNGBytes base64-encoded for use as a JWT
// claim value (and for substitution into the SVG card template).
var genericFacePNG = base64.StdEncoding.EncodeToString(genericFacePNGBytes)

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

	writeJSON(outputDir, "pid.json", genPID(pids, &input))
	writeJSON(outputDir, "eduid.json", genEduID(pids, &input))
	writeJSON(outputDir, "ehic.json", genEHIC(pids, &input))
	writeJSON(outputDir, "pda1.json", genPDA1(pids, &input))
	writeJSON(outputDir, "elm.json", genELM(pids, &input))
	writeJSON(outputDir, "diploma.json", genDiploma(pids, &input))
	writeJSON(outputDir, "microcredential.json", genMicroCredential(pids, &input))
	writeJSON(outputDir, "identity_mappings.json", genIdentityMappings(pids, &input))

	fmt.Printf("Generated 7 credential files and identity_mappings.json for %d persons in %s\n", len(pids), outputDir)
}

// --- PID (urn:eudi:pid:1, ARF 1.7.1 / Rulebook v1.0) ---
//
// Age verification claims (age_equal_or_over.*, age_over_*, age_in_years,
// age_birth_year) were removed from PID in CIR 2024/2977; they now belong to
// a separate Age Verification Attestation.

func genPID(pids []string, input *InputFile) map[string]*vcclient.UploadRequest {
	result := make(map[string]*vcclient.UploadRequest, len(pids))
	now := time.Now()
	for _, pid := range pids {
		p := input.Persons[pid]

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
			"date_of_issuance":               now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
			"document_number":                or_(pidExt.DocumentNumber, fmt.Sprintf("doc-pid-%s", pid)),
			"personal_administrative_number": or_(pidExt.PersonalAdministrativeNumber, fmt.Sprintf("pan-%s", pid)),
			"picture":                        genericFacePNG,
			"birth_family_name":              or_(pidExt.BirthFamilyName, p.FamilyName),
			"birth_given_name":               or_(pidExt.BirthGivenName, p.GivenName),
			"sex":                            or_(pidExt.Sex, "0"),
			"email":                          or_(pidExt.EmailAddress, fmt.Sprintf("%s@example.com", strings.ReplaceAll(toLower(p.FamilyName), " ", "_"))),
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
		}

		result[pid] = &vcclient.UploadRequest{
			DocumentData: dd,
			Meta: &model.MetaData{
				AuthenticSource: "Skatteverket",
				Scope:           "pid",
				DocumentID:      fmt.Sprintf("document_id_pid_%s", pid),
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
			"picture":                        genericFacePNG,
			"birth_family_name":              or_(pidExt.BirthFamilyName, p.FamilyName),
			"birth_given_name":               or_(pidExt.BirthGivenName, p.GivenName),
			"sex":                            or_(pidExt.Sex, "0"),
			"email":                          or_(pidExt.EmailAddress, fmt.Sprintf("%s@example.com", strings.ReplaceAll(toLower(p.FamilyName), " ", "_"))),
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
				AuthenticSource: "SUNET",
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

		doc := &EHICDocument{
			PersonalAdministrativeNumber: e.PersonalAdministrativeNumber,
			IssuingAuthority: IssuingAuthority{
				ID:   or_(e.InstitutionID, "CLEISS"),
				Name: input.Defaults.IssuingAuthority,
			},
			IssuingCountry: or_(e.IssuingCountry, "FR"),
			DateOfExpiry:   e.DateOfExpiry,
			DateOfIssuance: e.DateOfIssuance,
			DocumentNumber: e.DocumentNumber,
			StartingDate:   now.Format("2006-01-02"),
			EndingDate:     now.AddDate(1, 0, 0).Format("2006-01-02"),
			AuthenticSource: AuthenticSource{
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
				AuthenticSource: "Skatteverket",
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

		employer := Employer{ID: "01", Name: "SUNET", Country: "SE"}
		if d.Employer != nil {
			employer = Employer{ID: d.Employer.ID, Name: d.Employer.Name, Country: d.Employer.Country}
		}

		wa := WorkAddress{
			Formatted:      "Tulegatan 11, Stockholm",
			Street_address: "Tulegatan",
			House_number:   "11",
			Postal_code:    "11353",
			Locality:       "Stockholm",
			Region:         "Stockholm",
			Country:        "SE",
		}
		if d.WorkAddress != nil {
			wa = WorkAddress{
				Formatted:      d.WorkAddress.Formatted,
				Street_address: d.WorkAddress.StreetAddress,
				House_number:   d.WorkAddress.HouseNumber,
				Postal_code:    d.WorkAddress.PostalCode,
				Locality:       d.WorkAddress.Locality,
				Region:         d.WorkAddress.Region,
				Country:        d.WorkAddress.Country,
			}
		}

		doc := &PDA1Document{
			PersonalAdministrativeNumber: d.PersonalAdministrativeNumber,
			Employer:                     employer,
			WorkAddress:                  wa,
			IssuingAuthority: IssuingAuthority{
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
			AuthenticSource: AuthenticSource{
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
				AuthenticSource: "Skatteverket",
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
				AuthenticSource: "Ladok",
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
				AuthenticSource: "Ladok",
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
				AuthenticSource: "Ladok",
				Scope:           "microcredential",
				DocumentID:      fmt.Sprintf("document_id_microcredential_%s", pid),
			},
			IdentityMappingIDs: []string{fmt.Sprintf("authentic_source_person_id_%s", pid)},
		}
	}
	return result
}

// --- Identity Mappings ---

func genIdentityMappings(pids []string, input *InputFile) map[string][]*model.IdentityMapping {
	result := make(map[string][]*model.IdentityMapping, len(pids))
	for _, pid := range pids {
		p := input.Persons[pid]
		authenticSourcePersonID := fmt.Sprintf("authentic_source_person_id_%s", pid)
		attrs := map[string]string{
			"family_name": p.FamilyName,
			"given_name":  p.GivenName,
			"birth_date":  p.BirthDate,
		}

		result[pid] = []*model.IdentityMapping{
			{
				AuthenticSourcePersonID: authenticSourcePersonID,
				AuthenticSource:         "Skatteverket",
				Attributes:              attrs,
			},
			{
				AuthenticSourcePersonID: authenticSourcePersonID,
				AuthenticSource:         "SUNET",
				Attributes:              attrs,
			},
			{
				AuthenticSourcePersonID: authenticSourcePersonID,
				AuthenticSource:         "Ladok",
				Attributes:              attrs,
			},
		}
	}
	return result
}

// --- Helpers ---

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
