package mdoc

import (
	"testing"
	"time"
)

func TestConstants(t *testing.T) {
	if DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("DocType = %s, want org.iso.18013.5.1.mDL", DocType)
	}
	if Namespace != "org.iso.18013.5.1" {
		t.Errorf("Namespace = %s, want org.iso.18013.5.1", Namespace)
	}
}

func TestMDoc_MandatoryFields(t *testing.T) {
	// Create an mDL holder
	mdoc := &MDoc{
		FamilyName:           "Smith",
		GivenName:            "John",
		BirthDate:            "1990-03-15",
		IssueDate:            "2023-01-15",
		ExpiryDate:           "2033-01-15",
		IssuingCountry:       "SE",
		IssuingAuthority:     "Transportstyrelsen",
		DocumentNumber:       "SE123456789",
		Portrait:             []byte{0xFF, 0xD8, 0xFF, 0xE0}, // JPEG magic bytes
		UNDistinguishingSign: "S",
		DrivingPrivileges: []DrivingPrivilege{
			{VehicleCategoryCode: "B"},
		},
	}

	if mdoc.FamilyName != "Smith" {
		t.Errorf("FamilyName = %s, want Smith", mdoc.FamilyName)
	}
	if mdoc.GivenName != "John" {
		t.Errorf("GivenName = %s, want John", mdoc.GivenName)
	}
	if mdoc.IssuingCountry != "SE" {
		t.Errorf("IssuingCountry = %s, want SE", mdoc.IssuingCountry)
	}
	if len(mdoc.DrivingPrivileges) != 1 {
		t.Errorf("DrivingPrivileges length = %d, want 1", len(mdoc.DrivingPrivileges))
	}
}

func TestMDoc_OptionalFields(t *testing.T) {
	height := uint(180)
	weight := uint(75)
	sex := uint(1)
	eyeColour := "blue"
	hairColour := "blond"
	birthPlace := "Boston, USA"
	residentCity := "Cambridge"
	residentState := "Massachusetts"
	residentPostalCode := "75236"
	residentCountry := "SE"
	nationality := "SE"
	jurisdiction := "SE-C"
	adminNumber := "ADM-123456"
	familyNameNat := "Smith"
	givenNameNat := "John"
	ageInYears := uint(34)
	ageBirthYear := uint(1990)
	captureDate := time.Now()

	mdoc := &MDoc{
		FamilyName:           "Smith",
		GivenName:            "John",
		BirthDate:            "1990-03-15",
		IssueDate:            "2023-01-15",
		ExpiryDate:           "2033-01-15",
		IssuingCountry:       "SE",
		IssuingAuthority:     "Transportstyrelsen",
		DocumentNumber:       "SE123456789",
		Portrait:             []byte{0xFF, 0xD8},
		UNDistinguishingSign: "S",
		DrivingPrivileges:    []DrivingPrivilege{{VehicleCategoryCode: "B"}},
		// Optional fields
		Height:                      &height,
		Weight:                      &weight,
		Sex:                         &sex,
		EyeColour:                   &eyeColour,
		HairColour:                  &hairColour,
		BirthPlace:                  &birthPlace,
		ResidentCity:                &residentCity,
		ResidentState:               &residentState,
		ResidentPostalCode:          &residentPostalCode,
		ResidentCountry:             &residentCountry,
		Nationality:                 &nationality,
		IssuingJurisdiction:         &jurisdiction,
		AdministrativeNumber:        &adminNumber,
		FamilyNameNationalCharacter: &familyNameNat,
		GivenNameNationalCharacter:  &givenNameNat,
		AgeInYears:                  &ageInYears,
		AgeBirthYear:                &ageBirthYear,
		PortraitCaptureDate:         &captureDate,
		AgeOver: &AgeOver{
			Over18: new(true),
			Over21: new(true),
			Over65: new(false),
		},
	}

	if *mdoc.Height != 180 {
		t.Errorf("Height = %d, want 180", *mdoc.Height)
	}
	if *mdoc.Sex != 1 {
		t.Errorf("Sex = %d, want 1", *mdoc.Sex)
	}
	if !*mdoc.AgeOver.Over18 {
		t.Error("AgeOver.Over18 should be true")
	}
	if !*mdoc.AgeOver.Over21 {
		t.Error("AgeOver.Over21 should be true")
	}
	if *mdoc.AgeOver.Over65 {
		t.Error("AgeOver.Over65 should be false")
	}
}

func TestMDoc_BiometricTemplates(t *testing.T) {
	faceTemplate := []byte{0x01, 0x02, 0x03, 0x04}
	fingerTemplate := []byte{0x05, 0x06, 0x07, 0x08}
	signatureTemplate := []byte{0x09, 0x0A, 0x0B, 0x0C}
	signatureImage := []byte{0xFF, 0xD8, 0xFF, 0xE0}

	mdoc := &MDoc{
		FamilyName:                   "Johnson",
		GivenName:                    "Jane",
		BirthDate:                    "1985-07-20",
		IssueDate:                    "2024-01-01",
		ExpiryDate:                   "2034-01-01",
		IssuingCountry:               "SE",
		IssuingAuthority:             "Transportstyrelsen",
		DocumentNumber:               "SE987654321",
		Portrait:                     []byte{0xFF, 0xD8},
		UNDistinguishingSign:         "S",
		DrivingPrivileges:            []DrivingPrivilege{{VehicleCategoryCode: "B"}},
		BiometricTemplateFace:        faceTemplate,
		BiometricTemplateFingerprint: fingerTemplate,
		BiometricTemplateSignature:   signatureTemplate,
		SignatureUsualMark:           signatureImage,
	}

	if len(mdoc.BiometricTemplateFace) != 4 {
		t.Errorf("BiometricTemplateFace length = %d, want 4", len(mdoc.BiometricTemplateFace))
	}
	if len(mdoc.SignatureUsualMark) != 4 {
		t.Errorf("SignatureUsualMark length = %d, want 4", len(mdoc.SignatureUsualMark))
	}
}

func TestDrivingPrivilege_Basic(t *testing.T) {
	issueDate := "2023-01-15"
	expiryDate := "2033-01-15"

	privilege := DrivingPrivilege{
		VehicleCategoryCode: "B",
		IssueDate:           &issueDate,
		ExpiryDate:          &expiryDate,
	}

	if privilege.VehicleCategoryCode != "B" {
		t.Errorf("VehicleCategoryCode = %s, want B", privilege.VehicleCategoryCode)
	}
	if *privilege.IssueDate != issueDate {
		t.Errorf("IssueDate = %s, want %s", *privilege.IssueDate, issueDate)
	}
}

func TestDrivingPrivilege_WithCodes(t *testing.T) {
	// Swedish driving licence with restrictions
	sign := "="
	value := "automatic transmission only"

	privilege := DrivingPrivilege{
		VehicleCategoryCode: "B",
		Codes: []DrivingPrivilegeCode{
			{
				Code:  "78",
				Sign:  &sign,
				Value: &value,
			},
			{
				Code: "01.06",
			},
		},
	}

	if len(privilege.Codes) != 2 {
		t.Errorf("Codes length = %d, want 2", len(privilege.Codes))
	}
	if privilege.Codes[0].Code != "78" {
		t.Errorf("Codes[0].Code = %s, want 78", privilege.Codes[0].Code)
	}
	if *privilege.Codes[0].Value != value {
		t.Errorf("Codes[0].Value = %s, want %s", *privilege.Codes[0].Value, value)
	}
}

func TestDrivingPrivilege_AllCategories(t *testing.T) {
	// Test all standard EU driving licence categories
	categories := []string{"AM", "A1", "A2", "A", "B1", "B", "BE", "C1", "C1E", "C", "CE", "D1", "D1E", "D", "DE"}

	privileges := make([]DrivingPrivilege, len(categories))
	for i, cat := range categories {
		privileges[i] = DrivingPrivilege{VehicleCategoryCode: cat}
	}

	if len(privileges) != 15 {
		t.Errorf("Expected 15 EU categories, got %d", len(privileges))
	}
}

func TestDeviceKeyInfo(t *testing.T) {
	deviceKey := []byte{0xA1, 0x01, 0x02} // Sample COSE_Key

	info := DeviceKeyInfo{
		DeviceKey: deviceKey,
		KeyAuthorizations: &KeyAuthorizations{
			NameSpaces: []string{Namespace},
			DataElements: map[string][]string{
				Namespace: {"family_name", "given_name", "birth_date"},
			},
		},
		KeyInfo: map[string]any{
			"issuer": "SUNET",
		},
	}

	if len(info.DeviceKey) != 3 {
		t.Errorf("DeviceKey length = %d, want 3", len(info.DeviceKey))
	}
	if len(info.KeyAuthorizations.NameSpaces) != 1 {
		t.Errorf("NameSpaces length = %d, want 1", len(info.KeyAuthorizations.NameSpaces))
	}
	if len(info.KeyAuthorizations.DataElements[Namespace]) != 3 {
		t.Errorf("DataElements length = %d, want 3", len(info.KeyAuthorizations.DataElements[Namespace]))
	}
}

func TestValidityInfo(t *testing.T) {
	now := time.Now()
	validFrom := now
	validUntil := now.AddDate(1, 0, 0)
	expectedUpdate := now.AddDate(0, 6, 0)

	validity := ValidityInfo{
		Signed:         now,
		ValidFrom:      validFrom,
		ValidUntil:     validUntil,
		ExpectedUpdate: &expectedUpdate,
	}

	if validity.ValidFrom.After(validity.ValidUntil) {
		t.Error("ValidFrom should be before ValidUntil")
	}
	if validity.ExpectedUpdate.After(validity.ValidUntil) {
		t.Error("ExpectedUpdate should be before ValidUntil")
	}
}

func TestMobileSecurityObject(t *testing.T) {
	now := time.Now()

	mso := MobileSecurityObject{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests: map[string]map[uint][]byte{
			Namespace: {
				0: []byte{0x01, 0x02, 0x03},
				1: []byte{0x04, 0x05, 0x06},
			},
		},
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey: []byte{0xA1, 0x01, 0x02},
		},
		DocType: DocType,
		ValidityInfo: ValidityInfo{
			Signed:     now,
			ValidFrom:  now,
			ValidUntil: now.AddDate(1, 0, 0),
		},
	}

	if mso.Version != "1.0" {
		t.Errorf("Version = %s, want 1.0", mso.Version)
	}
	if mso.DigestAlgorithm != "SHA-256" {
		t.Errorf("DigestAlgorithm = %s, want SHA-256", mso.DigestAlgorithm)
	}
	if mso.DocType != DocType {
		t.Errorf("DocType = %s, want %s", mso.DocType, DocType)
	}
	if len(mso.ValueDigests[Namespace]) != 2 {
		t.Errorf("ValueDigests[Namespace] length = %d, want 2", len(mso.ValueDigests[Namespace]))
	}
}

func TestIssuerSignedItem(t *testing.T) {
	item := IssuerSignedItem{
		DigestID:          0,
		Random:            make([]byte, 32),
		ElementIdentifier: "family_name",
		ElementValue:      "Smith",
	}

	if item.DigestID != 0 {
		t.Errorf("DigestID = %d, want 0", item.DigestID)
	}
	if item.ElementIdentifier != "family_name" {
		t.Errorf("ElementIdentifier = %s, want family_name", item.ElementIdentifier)
	}
	if item.ElementValue != "Smith" {
		t.Errorf("ElementValue = %v, want Smith", item.ElementValue)
	}
}

func TestIssuerSigned(t *testing.T) {
	issuerSigned := IssuerSigned{
		NameSpaces: map[string][]IssuerSignedItem{
			Namespace: {
				{DigestID: 0, Random: make([]byte, 16), ElementIdentifier: "family_name", ElementValue: "Smith"},
				{DigestID: 1, Random: make([]byte, 16), ElementIdentifier: "given_name", ElementValue: "John"},
			},
		},
		IssuerAuth: []byte{0xD2, 0x84}, // COSE_Sign1 prefix
	}

	if len(issuerSigned.NameSpaces[Namespace]) != 2 {
		t.Errorf("NameSpaces items = %d, want 2", len(issuerSigned.NameSpaces[Namespace]))
	}
	if len(issuerSigned.IssuerAuth) != 2 {
		t.Errorf("IssuerAuth length = %d, want 2", len(issuerSigned.IssuerAuth))
	}
}

func TestDeviceSigned(t *testing.T) {
	deviceSigned := DeviceSigned{
		NameSpaces: []byte{0xA0}, // Empty map
		DeviceAuth: DeviceAuth{
			DeviceSignature: []byte{0xD2, 0x84}, // COSE_Sign1
		},
	}

	if deviceSigned.DeviceAuth.DeviceSignature == nil {
		t.Error("DeviceSignature should not be nil")
	}
	if deviceSigned.DeviceAuth.DeviceMac != nil {
		t.Error("DeviceMac should be nil when DeviceSignature is set")
	}
}

func TestDeviceAuth_MAC(t *testing.T) {
	deviceAuth := DeviceAuth{
		DeviceMac: []byte{0xD1, 0x84}, // COSE_Mac0
	}

	if deviceAuth.DeviceMac == nil {
		t.Error("DeviceMac should not be nil")
	}
	if deviceAuth.DeviceSignature != nil {
		t.Error("DeviceSignature should be nil when DeviceMac is set")
	}
}

func TestDocument(t *testing.T) {
	doc := Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{
				Namespace: {{DigestID: 0, Random: make([]byte, 16), ElementIdentifier: "family_name", ElementValue: "Test"}},
			},
			IssuerAuth: []byte{0xD2},
		},
		DeviceSigned: DeviceSigned{
			NameSpaces: []byte{0xA0},
			DeviceAuth: DeviceAuth{DeviceSignature: []byte{0xD2}},
		},
	}

	if doc.DocType != DocType {
		t.Errorf("DocType = %s, want %s", doc.DocType, DocType)
	}
}

func TestDocument_WithErrors(t *testing.T) {
	doc := Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{},
			IssuerAuth: []byte{0xD2},
		},
		DeviceSigned: DeviceSigned{
			NameSpaces: []byte{0xA0},
			DeviceAuth: DeviceAuth{DeviceSignature: []byte{0xD2}},
		},
		Errors: map[string]map[string]int{
			Namespace: {
				"portrait": 1, // Data element not available
			},
		},
	}

	if doc.Errors[Namespace]["portrait"] != 1 {
		t.Errorf("Error code for portrait = %d, want 1", doc.Errors[Namespace]["portrait"])
	}
}

func TestDeviceResponse(t *testing.T) {
	response := DeviceResponse{
		Version: "1.0",
		Documents: []Document{
			{
				DocType: DocType,
				IssuerSigned: IssuerSigned{
					NameSpaces: map[string][]IssuerSignedItem{},
					IssuerAuth: []byte{0xD2},
				},
				DeviceSigned: DeviceSigned{
					NameSpaces: []byte{0xA0},
					DeviceAuth: DeviceAuth{DeviceSignature: []byte{0xD2}},
				},
			},
		},
		Status: 0,
	}

	if response.Version != "1.0" {
		t.Errorf("Version = %s, want 1.0", response.Version)
	}
	if response.Status != 0 {
		t.Errorf("Status = %d, want 0 (OK)", response.Status)
	}
	if len(response.Documents) != 1 {
		t.Errorf("Documents length = %d, want 1", len(response.Documents))
	}
}

func TestDeviceResponse_WithDocumentErrors(t *testing.T) {
	response := DeviceResponse{
		Version:   "1.0",
		Documents: nil,
		DocumentErrors: []map[string]int{
			{DocType: 10}, // Document not available
		},
		Status: 10,
	}

	if response.Status != 10 {
		t.Errorf("Status = %d, want 10", response.Status)
	}
	if len(response.DocumentErrors) != 1 {
		t.Errorf("DocumentErrors length = %d, want 1", len(response.DocumentErrors))
	}
}

func TestDeviceRequest(t *testing.T) {
	request := DeviceRequest{
		Version: "1.0",
		DocRequests: []DocRequest{
			{
				ItemsRequest: []byte{0xA1}, // CBOR encoded
			},
		},
	}

	if request.Version != "1.0" {
		t.Errorf("Version = %s, want 1.0", request.Version)
	}
	if len(request.DocRequests) != 1 {
		t.Errorf("DocRequests length = %d, want 1", len(request.DocRequests))
	}
}

func TestDocRequest_WithReaderAuth(t *testing.T) {
	docRequest := DocRequest{
		ItemsRequest: []byte{0xA1},
		ReaderAuth:   []byte{0xD2, 0x84}, // COSE_Sign1 reader authentication
	}

	if docRequest.ReaderAuth == nil {
		t.Error("ReaderAuth should not be nil")
	}
}

func TestItemsRequest(t *testing.T) {
	itemsRequest := ItemsRequest{
		DocType: DocType,
		NameSpaces: map[string]map[string]bool{
			Namespace: {
				"family_name": false, // false = no intent to retain
				"given_name":  false,
				"portrait":    true, // true = intent to retain
			},
		},
		RequestInfo: map[string]any{
			"purpose": "Age verification",
		},
	}

	if itemsRequest.DocType != DocType {
		t.Errorf("DocType = %s, want %s", itemsRequest.DocType, DocType)
	}
	if len(itemsRequest.NameSpaces[Namespace]) != 3 {
		t.Errorf("Requested elements = %d, want 3", len(itemsRequest.NameSpaces[Namespace]))
	}
	if !itemsRequest.NameSpaces[Namespace]["portrait"] {
		t.Error("portrait should have intent to retain = true")
	}
	if itemsRequest.RequestInfo["purpose"] != "Age verification" {
		t.Errorf("RequestInfo purpose = %v, want Age verification", itemsRequest.RequestInfo["purpose"])
	}
}

func TestMDoc_CBORRoundtrip(t *testing.T) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}

	mdoc := &MDoc{
		FamilyName:           "Williams",
		GivenName:            "David",
		BirthDate:            "1985-06-15",
		IssueDate:            "2024-01-01",
		ExpiryDate:           "2034-01-01",
		IssuingCountry:       "SE",
		IssuingAuthority:     "Transportstyrelsen",
		DocumentNumber:       "SE555666777",
		Portrait:             []byte{0xFF, 0xD8, 0xFF, 0xE0},
		UNDistinguishingSign: "S",
		DrivingPrivileges: []DrivingPrivilege{
			{VehicleCategoryCode: "B"},
			{VehicleCategoryCode: "AM"},
		},
	}

	// Marshal
	data, err := encoder.Marshal(mdoc)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal
	var decoded MDoc
	if err := encoder.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.FamilyName != mdoc.FamilyName {
		t.Errorf("FamilyName = %s, want %s", decoded.FamilyName, mdoc.FamilyName)
	}
	if decoded.IssuingCountry != mdoc.IssuingCountry {
		t.Errorf("IssuingCountry = %s, want %s", decoded.IssuingCountry, mdoc.IssuingCountry)
	}
	if len(decoded.DrivingPrivileges) != 2 {
		t.Errorf("DrivingPrivileges = %d, want 2", len(decoded.DrivingPrivileges))
	}
}

func TestIssuerSignedItem_CBORRoundtrip(t *testing.T) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}

	item := IssuerSignedItem{
		DigestID:          42,
		Random:            []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		ElementIdentifier: "issuing_authority",
		ElementValue:      "SUNET",
	}

	data, err := encoder.Marshal(item)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded IssuerSignedItem
	if err := encoder.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.DigestID != item.DigestID {
		t.Errorf("DigestID = %d, want %d", decoded.DigestID, item.DigestID)
	}
	if decoded.ElementIdentifier != item.ElementIdentifier {
		t.Errorf("ElementIdentifier = %s, want %s", decoded.ElementIdentifier, item.ElementIdentifier)
	}
}
