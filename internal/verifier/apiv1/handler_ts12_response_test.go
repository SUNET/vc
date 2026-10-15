package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ts12Rig is a verifier with a payment session open and a wallet stand-in
// that answers it the way the Kotlin/Swift SDKs do.
type ts12Rig struct {
	t      *testing.T
	client *Client
	key    *ecdsa.PrivateKey
	sessID string
}

func newTS12Rig(t *testing.T) *ts12Rig {
	t.Helper()
	return newTS12RigFor(t, scaDCQL("sca"), testPayment())
}

func newTS12RigFor(t *testing.T, dcql *openid4vp.DCQL, payment *UIPaymentRequest) *ts12Rig {
	t.Helper()
	ctx := t.Context()
	client := newSigningTestClient(t)
	client.cfg.Verifier.TS12.Enable = true
	log := logger.NewSimple("test")
	notifyService, _ := notify.New(ctx, client.cfg, log)
	client.notify = notifyService
	openid4vpClient, _ := openid4vp.New(ctx, &openid4vp.Config{})
	client.openid4vp = openid4vpClient
	client.jwtTrustVerifier = trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
		TrustEvaluator: trust.NewAllowAllEvaluator(),
		JWKSResolver:   trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{}),
		ParseX5C:       func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
		ParseJWK:       jose.ParseJWKToPublicKey,
		Log:            log,
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: dcql, Payment: payment})
	require.NoError(t, err)
	return &ts12Rig{t: t, client: client, key: key, sessID: reply.SessionID}
}

var scaGoodAMR = []any{
	map[string]any{"knowledge": "pin_6_or_more_digits"},
	map[string]any{"possession": "key_in_local_external_wscd"},
}

// kbClaims is what a conformant wallet adds for this session; mutate to break it.
func (r *ts12Rig) kbClaims(jti string) map[string]any {
	authCtx, err := r.client.cacheService.AuthContext.GetByID(r.t.Context(), r.sessID)
	require.NoError(r.t, err)
	hashes, err := openid4vp.HashTransactionData(authCtx.TransactionData, "sha-256")
	require.NoError(r.t, err)
	return map[string]any{
		"transaction_data_hashes":     hashes,
		"transaction_data_hashes_alg": "sha-256",
		"jti":                         jti,
		"response_mode":               "direct_post.jwt",
		"amr":                         scaGoodAMR,
	}
}

func (r *ts12Rig) post(kb map[string]any) error {
	r.t.Helper()
	ctx := r.t.Context()
	authCtx, err := r.client.cacheService.AuthContext.GetByID(ctx, r.sessID)
	require.NoError(r.t, err)
	tok := createTestSDJWTWithKBClaims(r.t, r.key, map[string]any{"given_name": "Ada"}, nil, authCtx.Nonce, authCtx.ClientID, kb)
	body, err := json.Marshal(openid4vp.VPResponse{VPToken: map[string][]string{"sca": {tok}}, State: authCtx.State})
	require.NoError(r.t, err)
	_, pub, err := r.client.ephemeralEncryptionKey(ctx, authCtx.EphemeralEncryptionKeyID)
	require.NoError(r.t, err)
	enc, err := jwe.Encrypt(body, jwe.WithKey(jwa.ECDH_ES(), pub), jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(r.t, err)
	_, err = r.client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(enc)})
	return err
}

func TestVerificationDirectPost_TS12Payment(t *testing.T) {
	t.Run("a conformant presentation is accepted", func(t *testing.T) {
		r := newTS12Rig(t)
		require.NoError(t, r.post(r.kbClaims("jti-ok-1")))
	})

	refused := map[string]func(kb map[string]any){
		"no transaction_data_hashes": func(kb map[string]any) {
			delete(kb, "transaction_data_hashes")
			delete(kb, "transaction_data_hashes_alg")
		},
		"hash of something else": func(kb map[string]any) {
			kb["transaction_data_hashes"] = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		},
		"alg as array (wallet-common)": func(kb map[string]any) { kb["transaction_data_hashes_alg"] = []string{"sha-256"} },
		"single-factor RFC 8176 amr":   func(kb map[string]any) { kb["amr"] = []string{"hwk", "pop"} },
		"one category only":            func(kb map[string]any) { kb["amr"] = []any{map[string]any{"possession": "key_in_remote_wscd"}} },
		"no jti":                       func(kb map[string]any) { delete(kb, "jti") },
		"wrong response_mode":          func(kb map[string]any) { kb["response_mode"] = "direct_post" },
		"no response_mode":             func(kb map[string]any) { delete(kb, "response_mode") },
	}
	for name, mutate := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			r := newTS12Rig(t)
			kb := r.kbClaims("jti-" + name)
			mutate(kb)
			err := r.post(kb)
			require.Error(t, err)
			assert.Contains(t, err.Error(), openid4vp.ErrorInvalidTransactionData)
		})
	}

	t.Run("a plain presentation of a payment request is refused", func(t *testing.T) {
		r := newTS12Rig(t)
		err := r.post(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), openid4vp.ErrorInvalidTransactionData)
	})

	t.Run("the same jti is refused in a second session", func(t *testing.T) {
		first := newTS12Rig(t)
		require.NoError(t, first.post(first.kbClaims("replayed-jti")))
		second := newTS12Rig(t)
		second.client.cacheService.UsedJTI = first.client.cacheService.UsedJTI
		err := second.post(second.kbClaims("replayed-jti"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "jti has been used before")
	})

	t.Run("no replay store refuses", func(t *testing.T) {
		r := newTS12Rig(t)
		r.client.cacheService.UsedJTI = nil
		err := r.post(r.kbClaims("jti-nostore"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no replay store")
	})
}

// A payment bound to one credential of two: the other credential's
// presentation owes no hashes, and the bound one still does.
func TestVerificationDirectPost_TS12ScopedToTheBoundCredential(t *testing.T) {
	dcql := scaDCQL("sca")
	dcql.Credentials = append(dcql.Credentials, openid4vp.CredentialQuery{
		ID: "age", Format: openid4vp.FormatSDJWTVC, Meta: openid4vp.MetaQuery{VCTValues: []string{"https://example.com/age"}},
	})
	p := testPayment()
	p.CredentialID = "sca"

	answer := func(r *ts12Rig, scaKB map[string]any) error {
		ctx := r.t.Context()
		authCtx, err := r.client.cacheService.AuthContext.GetByID(ctx, r.sessID)
		require.NoError(r.t, err)
		mk := func(kb map[string]any) string {
			return createTestSDJWTWithKBClaims(r.t, r.key, map[string]any{"given_name": "Ada"}, nil, authCtx.Nonce, authCtx.ClientID, kb)
		}
		body, err := json.Marshal(openid4vp.VPResponse{VPToken: map[string][]string{"sca": {mk(scaKB)}, "age": {mk(nil)}}, State: authCtx.State})
		require.NoError(r.t, err)
		_, pub, err := r.client.ephemeralEncryptionKey(ctx, authCtx.EphemeralEncryptionKeyID)
		require.NoError(r.t, err)
		enc, err := jwe.Encrypt(body, jwe.WithKey(jwa.ECDH_ES(), pub), jwe.WithContentEncryption(jwa.A256GCM()))
		require.NoError(r.t, err)
		_, err = r.client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(enc)})
		return err
	}

	r := newTS12RigFor(t, dcql, p)
	require.NoError(t, answer(r, r.kbClaims("scoped-ok")))

	r = newTS12RigFor(t, dcql, p)
	err := answer(r, nil)
	require.Error(t, err, "the bound credential must carry the hashes even if the other one does not")
	assert.Contains(t, err.Error(), openid4vp.ErrorInvalidTransactionData)
}
