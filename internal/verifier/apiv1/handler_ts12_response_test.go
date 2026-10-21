package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/httphelpers"
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
	if kb != nil {
		if _, set := kb["_vct"]; !set {
			kb["_vct"] = "https://psp.example/sca"
		}
	}
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
			assert.Equal(t, http.StatusBadRequest, httphelpers.StatusCode(t.Context(), err))
		})
	}

	t.Run("refuses a credential of another type", func(t *testing.T) {
		r := newTS12Rig(t)
		kb := r.kbClaims("jti-othertype")
		kb["_vct"] = "urn:eudi:pid:1"
		err := r.post(kb)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not one the request asked for")
	})
	t.Run("refuses a credential with no vct", func(t *testing.T) {
		r := newTS12Rig(t)
		kb := r.kbClaims("jti-novct")
		kb["_vct"] = ""
		err := r.post(kb)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no vct")
	})

	// The modes come from what the session was issued with, not from the
	// configuration of whichever node receives the response.
	t.Run("response_mode is checked against the issued modes, not the current config", func(t *testing.T) {
		r := newTS12Rig(t)
		r.client.cfg.Verifier.DigitalCredentials.Enable = true // enabled after issuance
		kb := r.kbClaims("jti-mode-1")
		kb["response_mode"] = "dc_api.jwt"
		err := r.post(kb)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not one this request was issued with")

		r = newTS12Rig(t)
		authCtx, err := r.client.cacheService.AuthContext.GetByID(t.Context(), r.sessID)
		require.NoError(t, err)
		authCtx.TransactionDataResponseModes = []string{"direct_post.jwt", "dc_api.jwt"} // issued with the DC API on
		require.NoError(t, r.client.cacheService.AuthContext.Update(t.Context(), authCtx))
		r.client.cfg.Verifier.DigitalCredentials.Enable = false // disabled since
		kb = r.kbClaims("jti-mode-2")
		kb["response_mode"] = "dc_api.jwt"
		require.NoError(t, r.post(kb))
	})

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

	// The jti is recorded only once the issuer is authenticated: a credential
	// the trust policy rejects must not reserve its jti.
	t.Run("an untrusted issuer does not burn the jti", func(t *testing.T) {
		r := newTS12Rig(t)
		r.client.jwtTrustVerifier = trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
			TrustEvaluator: denyAllEvaluator{},
			JWKSResolver:   trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{}),
			ParseX5C:       func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
			ParseJWK:       jose.ParseJWKToPublicKey,
			Log:            logger.NewSimple("test"),
		})
		err := r.post(r.kbClaims("untrusted-jti"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer trust evaluation failed")
		fresh, err := r.client.cacheService.UsedJTI.SetNX(t.Context(), "untrusted-jti", true)
		require.NoError(t, err)
		assert.True(t, fresh, "the jti of a rejected presentation must still be unclaimed")
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
		sca := map[string]any{"_vct": "https://psp.example/sca"}
		for k, v := range scaKB {
			sca[k] = v
		}
		body, err := json.Marshal(openid4vp.VPResponse{VPToken: map[string][]string{"sca": {mk(sca)}, "age": {mk(nil)}}, State: authCtx.State})
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

// A response refused after the SCA credential passed must not use up its jti.
func TestVerificationDirectPost_TS12LaterRefusalDoesNotBurnTheJTI(t *testing.T) {
	dcql := scaDCQL("sca")
	dcql.Credentials = append(dcql.Credentials, openid4vp.CredentialQuery{
		ID: "age", Format: openid4vp.FormatSDJWTVC, Meta: openid4vp.MetaQuery{VCTValues: []string{"https://example.com/age"}},
	})
	p := testPayment()
	p.CredentialID = "sca"
	r := newTS12RigFor(t, dcql, p)

	ctx := t.Context()
	authCtx, err := r.client.cacheService.AuthContext.GetByID(ctx, r.sessID)
	require.NoError(t, err)
	sca := r.kbClaims("later-refusal-jti")
	sca["_vct"] = "https://psp.example/sca"
	scaTok := createTestSDJWTWithKBClaims(t, r.key, map[string]any{"given_name": "Ada"}, nil, authCtx.Nonce, authCtx.ClientID, sca)
	// The second credential fails its own nonce check, after the SCA one passed.
	ageTok := createTestSDJWTWithKBClaims(t, r.key, map[string]any{"given_name": "Ada"}, nil, "wrong-nonce", authCtx.ClientID, nil)
	body, err := json.Marshal(openid4vp.VPResponse{VPToken: map[string][]string{"sca": {scaTok}, "age": {ageTok}}, State: authCtx.State})
	require.NoError(t, err)
	_, pub, err := r.client.ephemeralEncryptionKey(ctx, authCtx.EphemeralEncryptionKeyID)
	require.NoError(t, err)
	enc, err := jwe.Encrypt(body, jwe.WithKey(jwa.ECDH_ES(), pub), jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(t, err)
	_, err = r.client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(enc)})
	require.Error(t, err)

	fresh, err := r.client.cacheService.UsedJTI.SetNX(ctx, "later-refusal-jti", true)
	require.NoError(t, err)
	assert.True(t, fresh, "the jti of a refused response must still be unclaimed")
}

type denyAllEvaluator struct{}

func (denyAllEvaluator) Evaluate(_ context.Context, _ *trust.EvaluationRequest) (*trust.TrustDecision, error) {
	return &trust.TrustDecision{Trusted: false, Reason: "test: deny all"}, nil
}
func (denyAllEvaluator) SupportsKeyType(trust.KeyType) bool { return true }
