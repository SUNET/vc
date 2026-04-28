package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	"github.com/SUNET/vc/internal/apigw/auth_providers/samlsp"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/beevik/etree"
	samltypes "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSAMLIntegration_FullFlow tests the complete SAML authentication flow
// from metadata retrieval through credential issuance
func TestSAMLIntegration_FullFlow(t *testing.T) {
	// Setup test environment
	env := setupTestEnvironment(t)
	defer env.cleanup()

	// Test Steps:
	// 1. Verify SP metadata is accessible
	// 2. Initiate authentication request
	// 3. Simulate IdP response (SAML assertion)
	// 4. Process assertion and extract claims
	// 5. Verify credential issuance

	t.Run("Step1_VerifySPMetadata", func(t *testing.T) {
		testSPMetadata(t, env)
	})

	t.Run("Step2_InitiateAuthentication", func(t *testing.T) {
		testInitiateAuth(t, env)
	})

	t.Run("Step3_ProcessSAMLAssertion", func(t *testing.T) {
		testProcessAssertion(t, env)
	})

	t.Run("Step4_TransformClaims", func(t *testing.T) {
		testClaimTransformation(t, env)
	})
}

// TestSAMLIntegration_MultipleCredentialTypes tests issuing different credential types
func TestSAMLIntegration_MultipleCredentialTypes(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	credentialTypes := []string{"pid", "diploma", "ehic"}

	for _, credType := range credentialTypes {
		t.Run(fmt.Sprintf("CredentialType_%s", credType), func(t *testing.T) {
			testCredentialTypeFlow(t, env, credType)
		})
	}
}

// TestSAMLIntegration_ErrorHandling tests error scenarios
func TestSAMLIntegration_ErrorHandling(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	t.Run("InvalidIdPEntityID", func(t *testing.T) {
		testInvalidIdP(t, env)
	})

	t.Run("MissingRequiredAttributes", func(t *testing.T) {
		testMissingAttributes(t, env)
	})

	t.Run("ExpiredAssertion", func(t *testing.T) {
		testExpiredAssertion(t, env)
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		testInvalidSignature(t, env)
	})
}

// testEnvironment holds the test environment setup
type testEnvironment struct {
	samlSPService      *samlsp.Service
	mockIdPServer      *httptest.Server
	mockMDQServer      *httptest.Server
	samlSPSessionCache pkgcache.Cache[*samlsp.Session]
	log                *logger.Log
	config             *model.SAMLSP
	idpEntityID        string
	idpKey             *rsa.PrivateKey   // IdP signing key
	idpCert            *x509.Certificate // IdP signing certificate
	cleanup            func()
}

// setupTestEnvironment creates a complete test environment with mock IdP
func setupTestEnvironment(t *testing.T) *testEnvironment {
	ctx := t.Context()

	// Create logger
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	// Generate temporary test certificates
	certPath, keyPath, cleanupCerts := generateTestCertificates(t)

	// Generate IdP signing keypair
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idpCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	idpCertDER, err := x509.CreateCertificate(rand.Reader, &idpCertTemplate, &idpCertTemplate, &idpKey.PublicKey, idpKey)
	require.NoError(t, err)
	idpCert, err := x509.ParseCertificate(idpCertDER)
	require.NoError(t, err)

	// Setup mock IdP metadata server (MDQ)
	idpEntityID := "https://test-idp.example.com/idp"
	idpCertB64 := base64.StdEncoding.EncodeToString(idpCertDER)
	mockMDQServer := createMockMDQServer(t, idpEntityID, idpCertB64)

	// Setup mock IdP SSO endpoint
	mockIdPServer := createMockIdPServer(t)

	// Create test configuration
	config := createTestSAMLConfig(mockMDQServer.URL, mockIdPServer.URL, idpEntityID, certPath, keyPath)

	// Create session cache
	samlSPSessionCache := pkgcache.NewMemoryCache[*samlsp.Session](3600 * time.Second)

	// Create SAML service
	samlSPService, err := samlsp.New(ctx, config, samlSPSessionCache, log)
	require.NoError(t, err)
	require.NotNil(t, samlSPService)

	env := &testEnvironment{
		samlSPService:      samlSPService,
		mockIdPServer:      mockIdPServer,
		mockMDQServer:      mockMDQServer,
		samlSPSessionCache: samlSPSessionCache,
		log:                log,
		config:             config,
		idpEntityID:        idpEntityID,
		idpKey:             idpKey,
		idpCert:            idpCert,
		cleanup: func() {
			samlSPSessionCache.Stop()
			mockIdPServer.Close()
			mockMDQServer.Close()
			cleanupCerts()
		},
	}

	return env
}

// createTestSAMLConfig creates a test SAML configuration
func createTestSAMLConfig(mdqURL, idpSSOURL, idpEntityID, certPath, keyPath string) *model.SAMLSP {
	return &model.SAMLSP{
		Enable:          true,
		EntityID:         "https://issuer.example.com/saml",
		ACSEndpoint:      "https://issuer.example.com/saml/acs",
		MetadataURL:      "https://issuer.example.com/saml/metadata",
		MDQServer:        mdqURL,
		MetadataCacheTTL: 3600,
		CertificatePath:  certPath,
		PrivateKeyPath:   keyPath,
		SessionDuration:  3600,
		AttributeMapping: model.AttributeMapping{
			"urn:oid:2.5.4.42": {
				Claim: "given_name",
			},
			"urn:oid:2.5.4.4": {
				Claim: "family_name",
			},
			"urn:oid:1.3.6.1.5.5.7.9.1": {
				Claim: "birth_date",
			},
			"urn:eudi:degree": {
				Claim: "degree",
			},
			"urn:eudi:ehic:cardnumber": {
				Claim: "card_number",
			},
		},
	}
}

// createMockMDQServer creates a mock MDQ (Metadata Query) server
func createMockMDQServer(t *testing.T, idpEntityID, idpCertB64 string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only return metadata for the known IdP entity ID.
		// The MDQ client sends the entity ID as a URL-encoded path segment,
		// but r.URL.Path is the decoded form, so compare against "/"+entityID.
		if r.URL.Path != "/"+idpEntityID {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Return test IdP metadata with signing certificate
		metadata := fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://test-idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, idpEntityID, idpCertB64)

		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(metadata))
	}))
}

// createMockIdPServer creates a mock IdP SSO endpoint
func createMockIdPServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This would handle SSO requests - for testing we just verify it's called
		t.Logf("Mock IdP received SSO request: %s", r.URL.String())
		w.WriteHeader(http.StatusOK)
	}))
}

// testSPMetadata tests SP metadata retrieval
func testSPMetadata(t *testing.T, env *testEnvironment) {
	ctx := t.Context()

	metadata, err := env.samlSPService.GetSPMetadata(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, metadata)

	// Parse and validate metadata
	var entityDesc samltypes.EntityDescriptor
	err = xml.Unmarshal([]byte(metadata), &entityDesc)
	require.NoError(t, err)

	assert.Equal(t, env.config.EntityID, entityDesc.EntityID)
	assert.Len(t, entityDesc.SPSSODescriptors, 1)

	spDesc := entityDesc.SPSSODescriptors[0]
	assert.NotEmpty(t, spDesc.AssertionConsumerServices)

	// Verify ACS URL
	acsFound := false
	for _, acs := range spDesc.AssertionConsumerServices {
		if acs.Location == env.config.ACSEndpoint {
			acsFound = true
			break
		}
	}
	assert.True(t, acsFound, "ACS URL should be in metadata")
}

// testInitiateAuth tests authentication initiation
func testInitiateAuth(t *testing.T, env *testEnvironment) {
	ctx := t.Context()

	authReq, err := env.samlSPService.InitiateAuth(ctx, env.idpEntityID, "pid")
	require.NoError(t, err)
	require.NotNil(t, authReq)

	assert.NotEmpty(t, authReq.ID)
	assert.NotEmpty(t, authReq.RedirectURL)
	assert.Contains(t, authReq.RedirectURL, "test-idp.example.com/sso")
	assert.Contains(t, authReq.RedirectURL, "SAMLRequest=")

	// Note: Session is managed internally by the service
	t.Logf("Created session ID: %s", authReq.ID)
}

// testProcessAssertion tests SAML assertion processing
func testProcessAssertion(t *testing.T, env *testEnvironment) {
	// Create a test SAML assertion
	assertion := createTestAssertion(t, env.idpEntityID, env.config.EntityID)

	// Create transformer
	transformer, err := env.samlSPService.BuildTransformer()
	require.NoError(t, err)

	// Convert SAML AttributeStatements to simple map
	attributes := samlAttributesToMap(assertion.AttributeStatements)

	// Transform claims
	claims, err := transformer.TransformClaims(attributes)
	require.NoError(t, err)
	require.NotNil(t, claims)

	// Verify expected claims
	assert.Equal(t, "John", claims["given_name"])
	assert.Equal(t, "Doe", claims["family_name"])
	assert.Equal(t, "1990-01-01", claims["birth_date"])
}

// testClaimTransformation tests various claim transformation scenarios
func testClaimTransformation(t *testing.T, env *testEnvironment) {
	transformer, err := env.samlSPService.BuildTransformer()
	require.NoError(t, err)

	testCases := []struct {
		name        string
		attributes  []samltypes.AttributeStatement
		expected    map[string]any
		shouldError bool
	}{
		{
			name: "AllAttributes",
			attributes: []samltypes.AttributeStatement{
				{
					Attributes: []samltypes.Attribute{
						{Name: "urn:oid:2.5.4.42", Values: []samltypes.AttributeValue{{Value: "Alice"}}},
						{Name: "urn:oid:2.5.4.4", Values: []samltypes.AttributeValue{{Value: "Smith"}}},
						{Name: "urn:oid:1.3.6.1.5.5.7.9.1", Values: []samltypes.AttributeValue{{Value: "1985-05-15"}}},
					},
				},
			},
			expected: map[string]any{
				"given_name":  "Alice",
				"family_name": "Smith",
				"birth_date":  "1985-05-15",
			},
			shouldError: false,
		},
		{
			name: "WithDegreeAndCardNumber",
			attributes: []samltypes.AttributeStatement{
				{
					Attributes: []samltypes.Attribute{
						{Name: "urn:oid:2.5.4.42", Values: []samltypes.AttributeValue{{Value: "Bob"}}},
						{Name: "urn:oid:2.5.4.4", Values: []samltypes.AttributeValue{{Value: "Johnson"}}},
						{Name: "urn:eudi:degree", Values: []samltypes.AttributeValue{{Value: "Bachelor of Science"}}},
						{Name: "urn:eudi:ehic:cardnumber", Values: []samltypes.AttributeValue{{Value: "EHIC123"}}},
					},
				},
			},
			expected: map[string]any{
				"given_name":  "Bob",
				"family_name": "Johnson",
				"degree":      "Bachelor of Science",
				"card_number": "EHIC123",
			},
			shouldError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert AttributeStatements to simple map
			attributes := samlAttributesToMap(tc.attributes)

			claims, err := transformer.TransformClaims(attributes)

			if tc.shouldError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, claims)
			}
		})
	}
}

// testCredentialTypeFlow tests full flow for a specific credential type
func testCredentialTypeFlow(t *testing.T, env *testEnvironment, credentialType string) {
	ctx := t.Context()

	// Initiate auth
	authReq, err := env.samlSPService.InitiateAuth(ctx, env.idpEntityID, credentialType)
	require.NoError(t, err)
	assert.NotEmpty(t, authReq.RedirectURL)

	// Note: Session is managed internally by the service
	t.Logf("Created session for %s: %s", credentialType, authReq.ID)
}

// testInvalidIdP tests handling of invalid IdP entity ID
func testInvalidIdP(t *testing.T, env *testEnvironment) {
	ctx := t.Context()

	_, err := env.samlSPService.InitiateAuth(ctx, "https://invalid-idp.example.com", "pid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get IdP metadata")
}

// testMissingAttributes tests handling of missing required attributes
func testMissingAttributes(t *testing.T, env *testEnvironment) {
	transformer, err := env.samlSPService.BuildTransformer()
	require.NoError(t, err)

	// Assertion missing required attribute
	attributes := []samltypes.AttributeStatement{
		{
			Attributes: []samltypes.Attribute{
				{Name: "urn:oid:2.5.4.42", Values: []samltypes.AttributeValue{{Value: "John"}}},
				// Missing family_name and birth_date
			},
		},
	}

	// Convert to map
	attrMap := samlAttributesToMap(attributes)

	_, err = transformer.TransformClaims(attrMap)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required attribute")
}

// testExpiredAssertion tests handling of expired assertions
func testExpiredAssertion(t *testing.T, env *testEnvironment) {
	// Create assertion with past validity
	assertion := createExpiredAssertion(t, env.idpEntityID, env.config.EntityID)

	// This would be tested in the actual ACS endpoint validation
	// For now, verify the assertion structure
	assert.NotNil(t, assertion)
	// Check Conditions.NotOnOrAfter
	assert.True(t, assertion.Conditions.NotOnOrAfter.Before(time.Now()))
}

// testInvalidSignature tests that a SAML response signed with a wrong key is rejected
func testInvalidSignature(t *testing.T, env *testEnvironment) {
	ctx := t.Context()

	// Initiate auth to create a session
	authReq, err := env.samlSPService.InitiateAuth(ctx, env.idpEntityID, "pid")
	require.NoError(t, err)

	// Generate a different key (not the one in IdP metadata)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	wrongCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "wrong-idp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	wrongCertDER, err := x509.CreateCertificate(rand.Reader, &wrongCertTemplate, &wrongCertTemplate, &wrongKey.PublicKey, wrongKey)
	require.NoError(t, err)
	wrongCert, err := x509.ParseCertificate(wrongCertDER)
	require.NoError(t, err)

	// Build a signed SAML response using the WRONG key
	samlResponseB64 := createSignedSAMLResponse(t, env.idpEntityID, env.config.EntityID,
		env.config.ACSEndpoint, authReq.ID, wrongKey, wrongCert)

	// Process the response — should fail signature validation
	_, err = env.samlSPService.ProcessAssertion(ctx, samlResponseB64, authReq.RelayState)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse SAML response")
	t.Logf("Correctly rejected invalid signature: %v", err)
}

// createSignedSAMLResponse builds a complete, XML-signed SAML Response using
// the crewjam/saml IdentityProvider machinery. The response is signed with
// the provided key/cert and returned as a base64-encoded string suitable for
// passing to ProcessAssertion.
func createSignedSAMLResponse(t *testing.T, idpEntityID, spEntityID, acsURL, inResponseTo string, key *rsa.PrivateKey, cert *x509.Certificate) string {
	t.Helper()

	now := time.Now()

	// Build the assertion
	assertion := &samltypes.Assertion{
		ID:           fmt.Sprintf("id-%x", mustRandomBytes(t, 20)),
		IssueInstant: now,
		Version:      "2.0",
		Issuer: samltypes.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idpEntityID,
		},
		Subject: &samltypes.Subject{
			NameID: &samltypes.NameID{
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
				Value:  "user@example.com",
			},
			SubjectConfirmations: []samltypes.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &samltypes.SubjectConfirmationData{
						InResponseTo: inResponseTo,
						Recipient:    acsURL,
						NotOnOrAfter: now.Add(5 * time.Minute),
					},
				},
			},
		},
		Conditions: &samltypes.Conditions{
			NotBefore:    now.Add(-1 * time.Minute),
			NotOnOrAfter: now.Add(5 * time.Minute),
			AudienceRestrictions: []samltypes.AudienceRestriction{
				{Audience: samltypes.Audience{Value: spEntityID}},
			},
		},
		AttributeStatements: []samltypes.AttributeStatement{
			{
				Attributes: []samltypes.Attribute{
					{Name: "urn:oid:2.5.4.42", Values: []samltypes.AttributeValue{{Value: "John"}}},
					{Name: "urn:oid:2.5.4.4", Values: []samltypes.AttributeValue{{Value: "Doe"}}},
					{Name: "urn:oid:1.3.6.1.5.5.7.9.1", Values: []samltypes.AttributeValue{{Value: "1990-01-01"}}},
				},
			},
		},
	}

	// Build the response
	response := &samltypes.Response{
		Destination:  acsURL,
		ID:           fmt.Sprintf("id-%x", mustRandomBytes(t, 20)),
		InResponseTo: inResponseTo,
		IssueInstant: now,
		Version:      "2.0",
		Issuer: &samltypes.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idpEntityID,
		},
		Status: samltypes.Status{
			StatusCode: samltypes.StatusCode{
				Value: samltypes.StatusSuccess,
			},
		},
	}

	// Use the IdP's signing context to sign the assertion
	keyPair := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
	keyStore := dsig.TLSCertKeyStore(keyPair)
	signingContext := dsig.NewDefaultSigningContext(keyStore)
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	err := signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	require.NoError(t, err)

	// Sign the assertion element
	assertionEl := assertion.Element()
	signedAssertionEl, err := signingContext.SignEnveloped(assertionEl)
	require.NoError(t, err)

	// Build the response element and embed the signed assertion
	responseEl := response.Element()
	responseEl.AddChild(signedAssertionEl)

	// Serialize to XML
	doc := etree.NewDocument()
	doc.SetRoot(responseEl)
	xmlBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(xmlBytes)
}

// mustRandomBytes generates n random bytes, failing the test on error.
func mustRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// createTestAssertion creates a test SAML assertion with standard attributes
func createTestAssertion(t *testing.T, issuer, audience string) *samltypes.Assertion {
	now := time.Now()
	return &samltypes.Assertion{
		ID:           "assertion-" + base64.StdEncoding.EncodeToString([]byte(time.Now().String())),
		IssueInstant: now,
		Version:      "2.0",
		Issuer: samltypes.Issuer{
			Value: issuer,
		},
		Subject: &samltypes.Subject{
			NameID: &samltypes.NameID{
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				Value:  "user@example.com",
			},
		},
		Conditions: &samltypes.Conditions{
			NotBefore:    now,
			NotOnOrAfter: now.Add(5 * time.Minute),
			AudienceRestrictions: []samltypes.AudienceRestriction{
				{
					Audience: samltypes.Audience{Value: audience},
				},
			},
		},
		AttributeStatements: []samltypes.AttributeStatement{
			{
				Attributes: []samltypes.Attribute{
					{
						Name: "urn:oid:2.5.4.42",
						Values: []samltypes.AttributeValue{
							{Value: "John"},
						},
					},
					{
						Name: "urn:oid:2.5.4.4",
						Values: []samltypes.AttributeValue{
							{Value: "Doe"},
						},
					},
					{
						Name: "urn:oid:1.3.6.1.5.5.7.9.1",
						Values: []samltypes.AttributeValue{
							{Value: "1990-01-01"},
						},
					},
				},
			},
		},
	}
}

// createExpiredAssertion creates an assertion with expired validity
func createExpiredAssertion(t *testing.T, issuer, audience string) *samltypes.Assertion {
	past := time.Now().Add(-10 * time.Minute)
	return &samltypes.Assertion{
		ID:           "expired-assertion",
		IssueInstant: past,
		Version:      "2.0",
		Issuer: samltypes.Issuer{
			Value: issuer,
		},
		Conditions: &samltypes.Conditions{
			NotBefore:    past,
			NotOnOrAfter: past.Add(1 * time.Minute), // Already expired
		},
	}
}

// samlAttributesToMap converts SAML AttributeStatements to a simple map
// This helper extracts the first value from each attribute
func samlAttributesToMap(statements []samltypes.AttributeStatement) map[string]any {
	attributes := make(map[string]any)

	for _, stmt := range statements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) > 0 {
				attributes[attr.Name] = attr.Values[0].Value
			}
		}
	}

	return attributes
}

// generateTestCertificates creates temporary X.509 certificate and private key for testing
// Returns paths to cert and key files, and a cleanup function
func generateTestCertificates(t *testing.T) (certPath, keyPath string, cleanup func()) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-saml-sp",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "saml-test-*")
	require.NoError(t, err)

	// Write certificate to file
	certPath = filepath.Join(tmpDir, "test-cert.pem")
	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)
	certFile.Close()

	// Write private key to file
	keyPath = filepath.Join(tmpDir, "test-key.pem")
	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	err = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	require.NoError(t, err)
	keyFile.Close()

	// Return cleanup function
	cleanup = func() {
		os.RemoveAll(tmpDir)
	}

	return certPath, keyPath, cleanup
}

// TestSAMLIntegration_MetadataSignatureValidation tests that signed metadata
// is accepted when the signing cert matches and rejected when it doesn't.
func TestSAMLIntegration_MetadataSignatureValidation(t *testing.T) {
	ctx := t.Context()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	certPath, keyPath, cleanupCerts := generateTestCertificates(t)
	defer cleanupCerts()

	// Generate federation signing keypair
	fedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fedCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "test-federation"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	fedCertDER, err := x509.CreateCertificate(rand.Reader, &fedCertTemplate, &fedCertTemplate, &fedKey.PublicKey, fedKey)
	require.NoError(t, err)
	fedCert, err := x509.ParseCertificate(fedCertDER)
	require.NoError(t, err)

	// Write federation cert to temp file
	tmpDir := t.TempDir()
	fedCertPath := filepath.Join(tmpDir, "fed-signing.pem")
	fedCertFile, err := os.Create(fedCertPath)
	require.NoError(t, err)
	err = pem.Encode(fedCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: fedCertDER})
	require.NoError(t, err)
	fedCertFile.Close()

	// Generate IdP signing keypair (for the IdP's own signing cert in metadata)
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idpCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	idpCertDER, err := x509.CreateCertificate(rand.Reader, &idpCertTemplate, &idpCertTemplate, &idpKey.PublicKey, idpKey)
	require.NoError(t, err)
	idpCertB64 := base64.StdEncoding.EncodeToString(idpCertDER)

	idpEntityID := "https://test-idp.example.com/idp"

	// Build unsigned metadata XML
	metadataXML := fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="md1" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://test-idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, idpEntityID, idpCertB64)

	// Sign the metadata with federation key
	signedMetadata := signMetadataXML(t, metadataXML, fedKey, fedCert)

	t.Run("AcceptValidSignature", func(t *testing.T) {
		// Create MDQ server serving signed metadata
		mdqServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/"+idpEntityID {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			w.Write(signedMetadata)
		}))
		defer mdqServer.Close()

		config := createTestSAMLConfig(mdqServer.URL, "https://idp.example.com/sso", idpEntityID, certPath, keyPath)
		config.MetadataSigningCertPath = fedCertPath

		sessionCache := pkgcache.NewMemoryCache[*samlsp.Session](3600 * time.Second)
		defer sessionCache.Stop()

		svc, err := samlsp.New(ctx, config, sessionCache, log)
		require.NoError(t, err)

		_, err = svc.InitiateAuth(ctx, idpEntityID, "pid")
		require.NoError(t, err, "should accept validly signed metadata")
		t.Log("Correctly accepted validly signed metadata")
	})

	t.Run("RejectInvalidSignature", func(t *testing.T) {
		// Create a different signing key (attacker)
		attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		attackerCertTemplate := x509.Certificate{
			SerialNumber: big.NewInt(999),
			Subject:      pkix.Name{CommonName: "attacker"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		attackerCertDER, err := x509.CreateCertificate(rand.Reader, &attackerCertTemplate, &attackerCertTemplate, &attackerKey.PublicKey, attackerKey)
		require.NoError(t, err)
		attackerCert, err := x509.ParseCertificate(attackerCertDER)
		require.NoError(t, err)

		// Sign metadata with attacker key
		attackerSignedMetadata := signMetadataXML(t, metadataXML, attackerKey, attackerCert)

		mdqServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/"+idpEntityID {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			w.Write(attackerSignedMetadata)
		}))
		defer mdqServer.Close()

		config := createTestSAMLConfig(mdqServer.URL, "https://idp.example.com/sso", idpEntityID, certPath, keyPath)
		config.MetadataSigningCertPath = fedCertPath

		sessionCache := pkgcache.NewMemoryCache[*samlsp.Session](3600 * time.Second)
		defer sessionCache.Stop()

		svc, err := samlsp.New(ctx, config, sessionCache, log)
		require.NoError(t, err)

		_, err = svc.InitiateAuth(ctx, idpEntityID, "pid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
		t.Logf("Correctly rejected metadata signed by untrusted key: %v", err)
	})

	t.Run("RejectUnsignedWhenCertConfigured", func(t *testing.T) {
		// Serve unsigned metadata when signing cert is configured
		mdqServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/"+idpEntityID {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			w.Write([]byte(metadataXML))
		}))
		defer mdqServer.Close()

		config := createTestSAMLConfig(mdqServer.URL, "https://idp.example.com/sso", idpEntityID, certPath, keyPath)
		config.MetadataSigningCertPath = fedCertPath

		sessionCache := pkgcache.NewMemoryCache[*samlsp.Session](3600 * time.Second)
		defer sessionCache.Stop()

		svc, err := samlsp.New(ctx, config, sessionCache, log)
		require.NoError(t, err)

		_, err = svc.InitiateAuth(ctx, idpEntityID, "pid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
		t.Logf("Correctly rejected unsigned metadata: %v", err)
	})
}

// signMetadataXML signs an XML metadata document with the given key/cert
// and returns the signed XML bytes.
func signMetadataXML(t *testing.T, metadataXML string, key *rsa.PrivateKey, cert *x509.Certificate) []byte {
	t.Helper()

	doc := etree.NewDocument()
	err := doc.ReadFromString(metadataXML)
	require.NoError(t, err)

	keyPair := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
	keyStore := dsig.TLSCertKeyStore(keyPair)
	signingCtx := dsig.NewDefaultSigningContext(keyStore)
	signingCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	err = signingCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	require.NoError(t, err)

	signedEl, err := signingCtx.SignEnveloped(doc.Root())
	require.NoError(t, err)

	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signedEl)
	signedBytes, err := signedDoc.WriteToBytes()
	require.NoError(t, err)

	return signedBytes
}
