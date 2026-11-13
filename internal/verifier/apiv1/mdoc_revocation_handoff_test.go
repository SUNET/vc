package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/revocation"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const handoffMDDL = `{
	"format": "mso_mdoc",
	"doctype": "org.iso.18013.5.1.mDL",
	"claims": {"org.iso.18013.5.1": {
		"family_name": {"mandatory": true, "value_type": "tstr"}
	}}
}`

// recordingStatusChecker answers every status-list reference with a fixed status and remembers what it was asked.
type recordingStatusChecker struct {
	status revocation.Status
	refs   []*revocation.Reference
}

func (r *recordingStatusChecker) Supports(s revocation.Scheme) bool {
	return s == revocation.SchemeStatusList
}

func (r *recordingStatusChecker) Extract(claims map[string]any) *revocation.Reference {
	return revocation.ExtractStatusListReference(claims)
}

func (r *recordingStatusChecker) CheckStatus(_ context.Context, ref *revocation.Reference) (*revocation.CheckResult, error) {
	r.refs = append(r.refs, ref)
	return &revocation.CheckResult{Status: r.status, URI: ref.URI, Index: ref.Index}, nil
}

// issueHandoffMDoc issues a signed mdoc, with a status reference when status is set, as a vp_token.
func issueHandoffMDoc(t *testing.T, status *mdoc.MSOStatusList) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Country: []string{"SE"}, Organization: []string{"Test Issuer"}, CommonName: "Test Document Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	issuer, err := mdoc.NewIssuer(mdoc.IssuerConfig{
		SignerKey:        key,
		CertificateChain: []*x509.Certificate{cert},
		DefaultValidity:  time.Hour,
	})
	require.NoError(t, err)
	schema, err := mdoc.LoadMDDLSchema([]byte(handoffMDDL))
	require.NoError(t, err)
	deviceKey, err := mdoc.GenerateDeviceKeyPair(elliptic.P256())
	require.NoError(t, err)

	issued, err := issuer.Issue(&mdoc.IssuanceRequest{
		DocumentData:    []byte(`{"family_name":"Andersson"}`),
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          schema,
		Status:          status,
	})
	require.NoError(t, err)

	encoder, err := mdoc.NewCBOREncoder()
	require.NoError(t, err)
	raw, err := encoder.Marshal(issued.DocumentMdoc)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// postMDoc sends vpToken through VerificationDirectPost with revocation enabled and fail_open off.
func postMDoc(t *testing.T, vpToken string, checker *recordingStatusChecker) error {
	t.Helper()
	ctx := t.Context()

	client, _ := CreateTestClientWithMock(t, nil)
	log := logger.NewSimple("test")
	notifyService, err := notify.New(ctx, client.cfg, log)
	require.NoError(t, err)
	client.notify = notifyService
	client.trustEvaluator = trust.NewAllowAllEvaluator()

	failOpen := false
	client.cfg.Verifier.Revocation = &model.RevocationConfig{Enabled: true, FailOpen: &failOpen}
	client.revocationRegistry = revocation.NewRegistry(checker)

	const kid = "handoff-kid"
	_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(ctx, kid)
	require.NoError(t, err)

	authCtx := &cache.AuthorizationContext{
		SessionID:                "handoff-session",
		State:                    "handoff-state",
		Nonce:                    "handoff-nonce",
		ClientID:                 "x509_san_dns:verifier.example.com",
		Scopes:                   []string{"mdl"},
		EphemeralEncryptionKeyID: kid,
	}
	require.NoError(t, client.cacheService.AuthContext.Save(ctx, authCtx))

	body, err := json.Marshal(openid4vp.VPResponse{VPToken: map[string][]string{"mdl": {vpToken}}, State: authCtx.State})
	require.NoError(t, err)
	encrypted, err := jwe.Encrypt(body, jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK), jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(t, err)

	_, err = client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(encrypted)})
	return err
}

// The status the issuer signed into the MSO must reach the revocation registry,
// or a revoked mdoc is accepted without anyone noticing.
func TestVerificationDirectPost_MDocRevocationHandoff(t *testing.T) {
	const uri = "https://registry.example.com/statuslists/3"

	t.Run("valid credential is accepted and its reference reaches the registry", func(t *testing.T) {
		checker := &recordingStatusChecker{status: revocation.StatusValid}
		require.NoError(t, postMDoc(t, issueHandoffMDoc(t, &mdoc.MSOStatusList{URI: uri, Idx: 42}), checker))

		require.Len(t, checker.refs, 1)
		assert.Equal(t, uri, checker.refs[0].URI)
		assert.Equal(t, int64(42), checker.refs[0].Index)
	})

	t.Run("legacy credential without status is accepted unchecked", func(t *testing.T) {
		checker := &recordingStatusChecker{status: revocation.StatusInvalid}
		require.NoError(t, postMDoc(t, issueHandoffMDoc(t, nil), checker))
		assert.Empty(t, checker.refs)
	})

	for name, status := range map[string]revocation.Status{
		"revoked":   revocation.StatusInvalid,
		"suspended": revocation.StatusSuspended,
	} {
		t.Run(name+" credential is rejected", func(t *testing.T) {
			checker := &recordingStatusChecker{status: status}
			err := postMDoc(t, issueHandoffMDoc(t, &mdoc.MSOStatusList{URI: uri, Idx: 7}), checker)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "has been "+status.String())
			require.Len(t, checker.refs, 1)
		})
	}
}
