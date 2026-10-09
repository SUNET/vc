//go:build integration

package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authproviders "github.com/SUNET/vc/internal/apigw/auth_providers"
	"github.com/SUNET/vc/internal/apigw/auth_providers/samlsp"
	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/beevik/etree"
	samltypes "github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// samlDatastoreApiv1 records the calls the standalone SAML ACS datastore branch
// makes so the test can assert the branch was taken: a datastore scope must
// route through LookupDatastoreByIdentity (caching the pre-loaded document),
// never StoreVCIDocuments (which caches the transformed SAML claims).
type samlDatastoreApiv1 struct {
	unimplementedApiv1

	lookupCalled          bool
	lookupSessionID       string
	lookupScope           string
	lookupAuthenticSource string

	storeCalled bool
}

func (m *samlDatastoreApiv1) ResolveIdentifier(_ context.Context, _ string, _ map[string]any) (string, error) {
	return "person-001", nil
}

func (m *samlDatastoreApiv1) LookupDatastoreByIdentity(_ context.Context, sessionID, scope, authenticSource string, _ map[string]any, _ *model.DatastoreScope) error {
	m.lookupCalled = true
	m.lookupSessionID = sessionID
	m.lookupScope = scope
	m.lookupAuthenticSource = authenticSource
	return nil
}

func (m *samlDatastoreApiv1) StoreVCIDocuments(_ context.Context, _ string, _ map[string]*model.CompleteDocument) error {
	m.storeCalled = true
	return nil
}

// TestEndpointSAMLACS_StandaloneDatastoreCachesDocument is the endpoint-level
// regression test for the standalone (non-VCI) SAML datastore path. It drives a
// real SAML assertion through endpointSAMLACS and asserts that a datastore
// scope resolves identity against the scope's configured authentic_source,
// persists that namespace onto the pre-auth AuthorizationContext, and caches
// the pre-loaded datastore document via LookupDatastoreByIdentity instead of
// storing the transformed SAML claims. Helper-only coverage of
// LookupDatastoreByIdentity cannot catch this branch being removed or miswired.
func TestEndpointSAMLACS_StandaloneDatastoreCachesDocument(t *testing.T) {
	const (
		scope           = "ehic"
		authenticSource = "SUNET"
	)

	env := setupSAMLACSTestEnv(t, scope, authenticSource)

	ctx := t.Context()
	authReq, err := env.service.authProviders.SAML().InitiateAuth(ctx, env.idpEntityID, scope)
	require.NoError(t, err)

	samlResponseB64 := env.signSAMLResponse(t, authReq.ID)

	c, rec := newSAMLACSContext(samlResponseB64, authReq.RelayState)
	resp, err := env.service.endpointSAMLACS(ctx, c)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)

	m, ok := resp.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "success", m["status"])
	offer, ok := m["credential_offer"].(*openid4vci.CredentialOfferResult)
	require.True(t, ok)
	preAuthCode := offer.ID
	require.NotEmpty(t, preAuthCode)

	// The datastore branch must have been taken: the pre-loaded document is
	// looked up and cached under the pre-auth code, using the scope's
	// configured namespace — not the IdP entity ID.
	require.True(t, env.apiv1.lookupCalled, "datastore scope must route through LookupDatastoreByIdentity")
	assert.False(t, env.apiv1.storeCalled, "datastore scope must not cache the transformed SAML claims")
	assert.Equal(t, preAuthCode, env.apiv1.lookupSessionID)
	assert.Equal(t, scope, env.apiv1.lookupScope)
	assert.Equal(t, authenticSource, env.apiv1.lookupAuthenticSource)

	// The pre-auth context carries the datastore data source and configured
	// namespace, so token/credential redemption resolves the same identity.
	authCtx, err := env.service.cacheService.AuthContext.Get(ctx, &pkgcache.AuthorizationContext{SessionID: preAuthCode})
	require.NoError(t, err)
	assert.Equal(t, string(model.DataSourceDatastore), authCtx.DataSource)
	assert.Equal(t, authenticSource, authCtx.AuthenticSource)
}

// samlACSTestEnv bundles the wired service and the IdP signing material so the
// test can mint a valid, signed SAML response for the ACS endpoint.
type samlACSTestEnv struct {
	service     *Service
	apiv1       *samlDatastoreApiv1
	idpEntityID string
	spEntityID  string
	acsURL      string
	idpKey      *rsa.PrivateKey
	idpCert     *x509.Certificate
}

func (env *samlACSTestEnv) signSAMLResponse(t *testing.T, inResponseTo string) string {
	return signSAMLResponseForACS(t, env.idpEntityID, env.spEntityID, env.acsURL, inResponseTo, env.idpKey, env.idpCert)
}

func setupSAMLACSTestEnv(t *testing.T, scope, authenticSource string) *samlACSTestEnv {
	t.Helper()
	ctx := t.Context()

	log, err := logger.New("saml-acs-test", "", false)
	require.NoError(t, err)

	tracer, err := trace.NewForTesting(ctx, "saml-acs-test", log)
	require.NoError(t, err)

	certPath, keyPath := writeSPCertificates(t)

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

	idpEntityID := "https://test-idp.example.com/idp"
	mdqServer := newMockMDQServer(t, idpEntityID, base64.StdEncoding.EncodeToString(idpCertDER))
	t.Cleanup(mdqServer.Close)

	const (
		spEntityID = "https://issuer.example.com/saml"
		acsURL     = "https://issuer.example.com/saml/acs"
	)

	samlCfg := model.SAMLSP{
		Enable:                true,
		EntityID:              spEntityID,
		ACSEndpoint:           acsURL,
		MetadataURL:           "https://issuer.example.com/saml/metadata",
		MDQServer:             mdqServer.URL,
		MetadataCacheTTL:      3600,
		CertificatePath:       certPath,
		PrivateKeyPath:        keyPath,
		SessionDuration:       3600,
		AllowUnsignedMetadata: true,
		AttributeMapping: model.AttributeMapping{
			"urn:oid:2.5.4.42":                  {Claim: "given_name", Required: true},
			"urn:oid:2.5.4.4":                   {Claim: "family_name", Required: true},
			"urn:oid:1.3.6.1.5.5.7.9.1":         {Claim: "birth_date", Required: true},
			"urn:oid:0.9.2342.19200300.100.1.1": {Claim: "authentic_source_person_id"},
		},
	}

	samlSessionCache := pkgcache.NewMemoryCache[*samlsp.Session](3600 * time.Second)
	t.Cleanup(samlSessionCache.Stop)

	authProviders, err := authproviders.New(ctx, &model.APIGWAuthProviders{SAML: samlCfg}, samlSessionCache, nil, nil, nil, log)
	require.NoError(t, err)
	require.NotNil(t, authProviders.SAML())

	apiv1Mock := &samlDatastoreApiv1{}

	service := &Service{
		cfg: &model.Cfg{
			Common: &model.Common{},
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{IssuerURL: "https://issuer.example.com"},
				},
				DataSources: model.DataSources{
					Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
						scope: {
							AuthProvider:    model.AuthProviderSAML,
							AuthenticSource: authenticSource,
							AuthClaims:      []string{"authentic_source_person_id"},
						},
					}},
				},
			},
		},
		log:           log,
		tracer:        tracer,
		apiv1:         apiv1Mock,
		authProviders: authProviders,
		cacheService: &apigwcache.Service{
			AuthContext: apigwcache.NewTestMemoryStore(10 * time.Minute),
			Document:    apigwcache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute),
		},
	}

	return &samlACSTestEnv{
		service:     service,
		apiv1:       apiv1Mock,
		idpEntityID: idpEntityID,
		spEntityID:  spEntityID,
		acsURL:      acsURL,
		idpKey:      idpKey,
		idpCert:     idpCert,
	}
}

// newSAMLACSContext builds a gin.Context carrying the form fields the ACS
// endpoint reads from the IdP POST.
func newSAMLACSContext(samlResponseB64, relayState string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)

	form := url.Values{}
	form.Set("SAMLResponse", samlResponseB64)
	form.Set("RelayState", relayState)
	req := httptest.NewRequest(http.MethodPost, "/samlsp/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req
	return c, rec
}

func writeSPCertificates(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-saml-sp"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "sp-cert.pem")
	keyPath = filepath.Join(dir, "sp-key.pem")

	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	require.NoError(t, certFile.Close())

	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	require.NoError(t, keyFile.Close())

	return certPath, keyPath
}

func newMockMDQServer(t *testing.T, idpEntityID, idpCertB64 string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+idpEntityID {
			w.WriteHeader(http.StatusNotFound)
			return
		}
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
		_, _ = w.Write([]byte(metadata))
	}))
}

// signSAMLResponseForACS builds a complete, XML-signed SAML Response carrying
// the identity attributes a datastore scope resolves against, and returns it
// base64-encoded for the ACS endpoint.
func signSAMLResponseForACS(t *testing.T, idpEntityID, spEntityID, acsURL, inResponseTo string, key *rsa.PrivateKey, cert *x509.Certificate) string {
	t.Helper()
	now := time.Now()

	assertion := &samltypes.Assertion{
		ID:           fmt.Sprintf("id-%x", randomBytes(t, 20)),
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
					{Name: "urn:oid:0.9.2342.19200300.100.1.1", Values: []samltypes.AttributeValue{{Value: "person-001"}}},
				},
			},
		},
	}

	response := &samltypes.Response{
		Destination:  acsURL,
		ID:           fmt.Sprintf("id-%x", randomBytes(t, 20)),
		InResponseTo: inResponseTo,
		IssueInstant: now,
		Version:      "2.0",
		Issuer: &samltypes.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idpEntityID,
		},
		Status: samltypes.Status{
			StatusCode: samltypes.StatusCode{Value: samltypes.StatusSuccess},
		},
	}

	keyPair := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
	signingContext := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(keyPair))
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	require.NoError(t, signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod))

	signedAssertionEl, err := signingContext.SignEnveloped(assertion.Element())
	require.NoError(t, err)

	responseEl := response.Element()
	responseEl.AddChild(signedAssertionEl)

	doc := etree.NewDocument()
	doc.SetRoot(responseEl)
	xmlBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(xmlBytes)
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}
