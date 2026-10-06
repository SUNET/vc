package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// credentialAPI records the request the endpoint bound, so a test can assert
// that the JSON inside a JWE reached the handler intact.
type credentialAPI struct {
	unimplementedApiv1
	got         *openid4vci.CredentialRequest
	gotDeferred *openid4vci.DeferredCredentialRequest
	calls       int
	// deferredReturnsNothing makes VCIDeferredCredential behave the way the
	// production one does today: a stub returning (nil, nil).
	deferredReturnsNothing bool
}

func (a *credentialAPI) VCIDeferredCredential(_ context.Context, req *openid4vci.DeferredCredentialRequest) (*openid4vci.CredentialResponse, error) {
	a.gotDeferred = req
	a.calls++
	if a.deferredReturnsNothing {
		return nil, nil
	}
	return &openid4vci.CredentialResponse{
		Credentials: []openid4vci.Credential{{Credential: "the-deferred-credential"}},
	}, nil
}

func (a *credentialAPI) VCICredential(_ context.Context, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error) {
	a.got = req
	a.calls++
	return &openid4vci.CredentialResponse{
		Credentials: []openid4vci.Credential{{Credential: "the-credential"}},
	}, nil
}

// encryptionSetup is a wallet's view of a running Credential Endpoint: the
// route, the recorded API, and the issuer's published encryption key.
type encryptionSetup struct {
	engine     *gin.Engine
	api        *credentialAPI
	issuerKey  jwk.Key // the public key the metadata publishes, nil when keyless
	walletPriv jwk.Key // the wallet's own response key
	walletPub  json.RawMessage
}

func newEncryptionSetup(t *testing.T, requestRequired, responseRequired, keyless bool) *encryptionSetup {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	encCfg := model.CredentialEncryption{
		RequestEncryptionRequired:  &requestRequired,
		ResponseEncryptionRequired: &responseRequired,
	}
	if !keyless {
		encCfg.Keys = []model.CredentialEncryptionKey{{PrivateKeyPath: writeTestP256Key(t)}}
	}

	cfg := &model.Cfg{
		Common: &model.Common{},
		APIGW: &model.APIGW{
			IssuerMetadata: model.IssuerMetadata{CredentialEncryption: encCfg},
		},
	}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	api := &credentialAPI{}
	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       api,
		tracer:      tracer,
		httpHelpers: helpers,
	}
	s.credentialEncryption, err = cfg.APIGW.IssuerMetadata.CredentialEncryption.Load()
	require.NoError(t, err)

	engine := gin.New()
	rg := engine.Group("")
	helpers.Server.RegEndpoint(ctx, rg, http.MethodPost, "credential", http.StatusOK, s.endpointVCICredential)
	helpers.Server.RegEndpoint(ctx, rg, http.MethodPost, "deferred_credential", http.StatusOK, s.endpointVCIDeferredCredential)

	setup := &encryptionSetup{engine: engine, api: api}

	// The wallet reads the issuer's key out of the published metadata, which
	// is the same object the endpoint decrypts with.
	if metadata := s.credentialEncryption.RequestMetadata(); metadata != nil {
		set, err := jwk.Parse(metadata.JWKS)
		require.NoError(t, err)
		require.Equal(t, 1, set.Len())
		key, ok := set.Key(0)
		require.True(t, ok)
		setup.issuerKey = key
	}

	setup.walletPriv, setup.walletPub = newWalletKey(t)

	return setup
}

func writeTestP256Key(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "enc.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path
}

// newWalletKey returns a wallet's private response key and the public JWK it
// would put in credential_response_encryption.jwk - carrying an alg, which
// §8.3 requires.
func newWalletKey(t *testing.T) (jwk.Key, json.RawMessage) {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	priv, err := jwk.Import(raw)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.KeyIDKey, "wallet-response-key"))
	require.NoError(t, priv.Set(jwk.AlgorithmKey, openid4vci.AlgECDHESA256KW))

	pub, err := priv.PublicKey()
	require.NoError(t, err)
	encoded, err := json.Marshal(pub)
	require.NoError(t, err)

	return priv, encoded
}

// responseParams is what a wallet puts in credential_response_encryption.
func (e *encryptionSetup) responseParams(enc, zip string) map[string]any {
	params := map[string]any{"jwk": json.RawMessage(e.walletPub), "enc": enc}
	if zip != "" {
		params["zip"] = zip
	}
	return params
}

func (e *encryptionSetup) requestBody(t *testing.T, responseEncryption map[string]any) []byte {
	t.Helper()
	body := map[string]any{"credential_configuration_id": "pid"}
	if responseEncryption != nil {
		body["credential_response_encryption"] = responseEncryption
	}
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	return encoded
}

// encrypt wraps a request body the way a wallet would, from the key the
// issuer published. withKid and compress drive the two header cases that are
// refused.
func (e *encryptionSetup) encrypt(t *testing.T, plaintext []byte, withKid, compress bool) []byte {
	t.Helper()
	require.NotNil(t, e.issuerKey, "no issuer key was published")

	// jwx copies the key's own kid into the protected header, so dropping it
	// means encrypting with a key that has none.
	key := e.issuerKey
	if !withKid {
		clone, err := e.issuerKey.Clone()
		require.NoError(t, err)
		require.NoError(t, clone.Remove(jwk.KeyIDKey))
		key = clone
	}

	headers := jwe.NewHeaders()
	if withKid {
		kid, ok := e.issuerKey.KeyID()
		require.True(t, ok)
		require.NoError(t, headers.Set(jwe.KeyIDKey, kid))
	}

	options := []jwe.EncryptOption{
		jwe.WithKey(jwa.ECDH_ES_A256KW(), key),
		jwe.WithContentEncryption(jwa.A256GCM()),
		jwe.WithProtectedHeaders(headers),
	}
	if compress {
		options = append(options, jwe.WithCompress(jwa.Deflate()))
	}

	encrypted, err := jwe.Encrypt(plaintext, options...)
	require.NoError(t, err)
	return encrypted
}

func (e *encryptionSetup) post(t *testing.T, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	return e.postTo(t, "/credential", contentType, body)
}

func (e *encryptionSetup) postTo(t *testing.T, path, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "DPoP token")
	req.Header.Set("DPoP", "proof")
	w := httptest.NewRecorder()
	e.engine.ServeHTTP(w, req)
	return w
}

// decryptReply is the wallet opening the response with its own key.
func (e *encryptionSetup) decryptReply(t *testing.T, body string) map[string]any {
	t.Helper()
	plaintext, err := jwe.Decrypt([]byte(body), jwe.WithKey(jwa.ECDH_ES_A256KW(), e.walletPriv))
	require.NoError(t, err)

	var reply map[string]any
	require.NoError(t, json.Unmarshal(plaintext, &reply))
	return reply
}

func requireVCIError(t *testing.T, w *httptest.ResponseRecorder, code string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, code, body["error"], "body: %s", w.Body.String())
}

// The whole round trip: the wallet encrypts the request to the key the issuer
// published, the issuer decrypts it, issues, and encrypts the response back
// to the wallet's own key (SUNET/vc#707).
func TestCredentialEncryption_RoundTrip(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	plaintext := e.requestBody(t, e.responseParams(openid4vci.EncA256GCM, ""))
	w := e.post(t, openid4vci.MediaTypeJWT, e.encrypt(t, plaintext, true, false))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, openid4vci.MediaTypeJWT, w.Header().Get("Content-Type"))

	// The decrypted request reached the handler intact.
	require.Equal(t, 1, e.api.calls)
	assert.Equal(t, "pid", e.api.got.CredentialConfigurationID)
	assert.Equal(t, "DPoP token", e.api.got.Authorization, "headers survive the rewrite")

	reply := e.decryptReply(t, w.Body.String())
	credentials, ok := reply["credentials"].([]any)
	require.True(t, ok, "reply: %#v", reply)
	require.Len(t, credentials, 1)
	assert.Equal(t, "the-credential", credentials[0].(map[string]any)["credential"])
}

// zip is advertised for responses only, so a wallet may ask for it there.
func TestCredentialEncryption_ResponseCompression(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	plaintext := e.requestBody(t, e.responseParams(openid4vci.EncA256GCM, openid4vci.ZipDeflate))
	w := e.post(t, openid4vci.MediaTypeJWT, e.encrypt(t, plaintext, true, false))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	reply := e.decryptReply(t, w.Body.String())
	assert.NotEmpty(t, reply["credentials"])
}

// Nothing is required, so a plain JSON request is still the ordinary case.
func TestCredentialEncryption_PlainRequestStillWorks(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	w := e.post(t, gin.MIMEJSON, e.requestBody(t, nil))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	assert.Equal(t, 1, e.api.calls)
}

// §8.3: "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included, to prevent it being
// substituted by an attacker." A plaintext request carrying an encryption key
// is exactly the substitution that rule is about.
func TestCredentialEncryption_ResponseKeyOnAPlaintextRequestIsRefused(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	w := e.post(t, gin.MIMEJSON, e.requestBody(t, e.responseParams(openid4vci.EncA256GCM, "")))

	requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	assert.Zero(t, e.api.calls, "nothing is issued for a request that will be refused")
}

func TestCredentialEncryption_RequiredRequestRefusesPlaintext(t *testing.T) {
	e := newEncryptionSetup(t, true, false, false)

	w := e.post(t, gin.MIMEJSON, e.requestBody(t, nil))

	requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	assert.Zero(t, e.api.calls)
}

func TestCredentialEncryption_RequiredResponseRefusesAMissingKey(t *testing.T) {
	e := newEncryptionSetup(t, false, true, false)

	w := e.post(t, openid4vci.MediaTypeJWT, e.encrypt(t, e.requestBody(t, nil), true, false))

	requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	assert.Zero(t, e.api.calls)
}

// zip_values_supported is absent from credential_request_encryption, which
// §12.2.4 reads as supporting none - so a compressed request is refused
// before anything is inflated.
func TestCredentialEncryption_CompressedRequestIsRefused(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	w := e.post(t, openid4vci.MediaTypeJWT, e.encrypt(t, e.requestBody(t, nil), true, true))

	requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	assert.Zero(t, e.api.calls)
}

// Every published key carries a kid, so a request that names none was not
// built from this issuer's metadata.
func TestCredentialEncryption_RequestWithoutKidIsRefused(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	w := e.post(t, openid4vci.MediaTypeJWT, e.encrypt(t, e.requestBody(t, nil), false, false))

	requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	assert.Zero(t, e.api.calls)
}

func TestCredentialEncryption_MalformedJWEIsRefused(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	w := e.post(t, openid4vci.MediaTypeJWT, []byte("not.a.jwe"))

	requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	assert.Zero(t, e.api.calls)
}

// Leniency about the envelope is not leniency about the parameters inside it.
func TestCredentialEncryption_BadResponseParametersAreRefused(t *testing.T) {
	for name, params := range map[string]func(e *encryptionSetup) map[string]any{
		"unsupported enc": func(e *encryptionSetup) map[string]any {
			return e.responseParams("A128CBC-HS256", "")
		},
		"unsupported zip": func(e *encryptionSetup) map[string]any {
			return e.responseParams(openid4vci.EncA256GCM, "GZIP")
		},
		"jwk without alg": func(e *encryptionSetup) map[string]any {
			p := e.responseParams(openid4vci.EncA256GCM, "")
			var key map[string]any
			require.NoError(t, json.Unmarshal(e.walletPub, &key))
			delete(key, "alg")
			encoded, err := json.Marshal(key)
			require.NoError(t, err)
			p["jwk"] = json.RawMessage(encoded)
			return p
		},
		"jwk with an alg this issuer does not perform": func(e *encryptionSetup) map[string]any {
			p := e.responseParams(openid4vci.EncA256GCM, "")
			var key map[string]any
			require.NoError(t, json.Unmarshal(e.walletPub, &key))
			key["alg"] = "ECDH-ES+A128KW"
			encoded, err := json.Marshal(key)
			require.NoError(t, err)
			p["jwk"] = json.RawMessage(encoded)
			return p
		},
		// RFC 7517 §4.2. jwe.Encrypt takes this key explicitly and never
		// looks at use, so a signing key would be used for encryption and
		// the mistake would surface in the wallet, after issuance.
		"jwk declaring use sig": func(e *encryptionSetup) map[string]any {
			p := e.responseParams(openid4vci.EncA256GCM, "")
			var key map[string]any
			require.NoError(t, json.Unmarshal(e.walletPub, &key))
			key["use"] = "sig"
			encoded, err := json.Marshal(key)
			require.NoError(t, err)
			p["jwk"] = json.RawMessage(encoded)
			return p
		},
		// Absent is allowed: use is optional and claims nothing. This case
		// is here so the check above cannot be written as "reject unless
		// use is enc", which would refuse most wallets.
		"jwk declaring use enc": func(e *encryptionSetup) map[string]any {
			p := e.responseParams(openid4vci.EncA256GCM, "")
			var key map[string]any
			require.NoError(t, json.Unmarshal(e.walletPub, &key))
			key["use"] = "enc"
			key["alg"] = "ECDH-ES+A128KW" // the thing actually refused here
			encoded, err := json.Marshal(key)
			require.NoError(t, err)
			p["jwk"] = json.RawMessage(encoded)
			return p
		},
		"jwk that is not a key": func(e *encryptionSetup) map[string]any {
			p := e.responseParams(openid4vci.EncA256GCM, "")
			p["jwk"] = json.RawMessage(`{"kty":"EC"}`)
			return p
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEncryptionSetup(t, false, false, false)

			w := e.post(t, openid4vci.MediaTypeJWT, e.encrypt(t, e.requestBody(t, params(e)), true, false))

			requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
			assert.Zero(t, e.api.calls, "nothing is issued for a request that will be refused")
		})
	}
}

// With no key configured the issuer publishes neither encryption object, and
// says so rather than ignoring what the wallet asked for.
func TestCredentialEncryption_KeylessIssuerRefusesEncryption(t *testing.T) {
	e := newEncryptionSetup(t, false, false, true)
	require.Nil(t, e.issuerKey)

	t.Run("an encrypted request is refused", func(t *testing.T) {
		w := e.post(t, openid4vci.MediaTypeJWT, []byte("anything"))
		requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	})

	t.Run("a response encryption key is refused", func(t *testing.T) {
		w := e.post(t, gin.MIMEJSON, e.requestBody(t, e.responseParams(openid4vci.EncA256GCM, "")))
		requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	})

	t.Run("a plain request is unaffected", func(t *testing.T) {
		w := e.post(t, gin.MIMEJSON, e.requestBody(t, nil))
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	})
}

// The Deferred Credential Endpoint carries the same two rules. §9.1 makes the
// point explicitly: the parameters used are the ones in THIS request,
// "regardless of what was sent in the initial Credential Request".
func TestCredentialEncryption_DeferredRoundTrip(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	body, err := json.Marshal(map[string]any{
		"transaction_id":                 "txn-1",
		"credential_response_encryption": e.responseParams(openid4vci.EncA256GCM, ""),
	})
	require.NoError(t, err)

	w := e.postTo(t, "/deferred_credential", openid4vci.MediaTypeJWT, e.encrypt(t, body, true, false))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, openid4vci.MediaTypeJWT, w.Header().Get("Content-Type"))
	require.NotNil(t, e.api.gotDeferred)
	assert.Equal(t, "txn-1", e.api.gotDeferred.TransactionID)

	reply := e.decryptReply(t, w.Body.String())
	credentials, ok := reply["credentials"].([]any)
	require.True(t, ok, "reply: %#v", reply)
	assert.Equal(t, "the-deferred-credential", credentials[0].(map[string]any)["credential"])
}

func TestCredentialEncryption_DeferredResponseKeyOnAPlaintextRequestIsRefused(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	body, err := json.Marshal(map[string]any{
		"transaction_id":                 "txn-1",
		"credential_response_encryption": e.responseParams(openid4vci.EncA256GCM, ""),
	})
	require.NoError(t, err)

	w := e.postTo(t, "/deferred_credential", gin.MIMEJSON, body)

	requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	assert.Zero(t, e.api.calls)
}

// VCIDeferredCredential is a stub that returns (nil, nil). Encrypting that
// would hand the wallet a 200 carrying an encrypted "null" - a success it
// cannot tell from a credential it failed to read. The endpoint says what is
// actually true instead, whether or not encryption was asked for.
func TestCredentialEncryption_DeferredNilReplyIsNotAnEncryptedSuccess(t *testing.T) {
	body, err := json.Marshal(map[string]any{"transaction_id": "txn-1"})
	require.NoError(t, err)

	t.Run("plaintext", func(t *testing.T) {
		e := newEncryptionSetup(t, false, false, false)
		e.api.deferredReturnsNothing = true

		w := e.postTo(t, "/deferred_credential", gin.MIMEJSON, body)

		assert.NotEqual(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	})

	t.Run("encrypted", func(t *testing.T) {
		e := newEncryptionSetup(t, false, false, false)
		e.api.deferredReturnsNothing = true

		encBody, err := json.Marshal(map[string]any{
			"transaction_id":                 "txn-1",
			"credential_response_encryption": e.responseParams(openid4vci.EncA256GCM, ""),
		})
		require.NoError(t, err)

		w := e.postTo(t, "/deferred_credential", openid4vci.MediaTypeJWT, e.encrypt(t, encBody, true, false))

		require.NotEqual(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.NotEqual(t, openid4vci.MediaTypeJWT, w.Header().Get("Content-Type"),
			"an empty answer must not come back looking like an encrypted credential")
	})
}

// jwe.Parse accepts the JSON serialization as well as the compact one, and in
// JSON form a per-recipient header can carry parameters the protected header
// does not - zip among them, which would reach the decrypter and be inflated.
// §8.3 asks for a JWT, which is the compact form, so the JSON form is refused
// outright.
func TestCredentialEncryption_JSONSerializationIsRefused(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	kid, ok := e.issuerKey.KeyID()
	require.True(t, ok)
	headers := jwe.NewHeaders()
	require.NoError(t, headers.Set(jwe.KeyIDKey, kid))

	// The same message the round-trip test sends, serialized as JSON and
	// compressed in a per-recipient header rather than the protected one.
	encrypted, err := jwe.Encrypt(e.requestBody(t, nil),
		jwe.WithKey(jwa.ECDH_ES_A256KW(), e.issuerKey, jwe.WithPerRecipientHeaders(headers)),
		jwe.WithContentEncryption(jwa.A256GCM()),
		jwe.WithCompress(jwa.Deflate()),
		jwe.WithJSON(),
	)
	require.NoError(t, err)
	require.Contains(t, string(encrypted), "{", "this test is pointless unless the message is JSON-serialized")

	w := e.post(t, openid4vci.MediaTypeJWT, encrypted)

	requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	assert.Zero(t, e.api.calls)

	// Asserted on the reason, not just the refusal: without the
	// serialization check this message is refused for a missing protected
	// "alg" instead, which is incidental - the JSON form can put alg in the
	// per-recipient header and pass that check while still carrying zip.
	assert.Contains(t, w.Body.String(), "compact serialization")
}

// jwk.Key.Validate checks a key's internal structure, not whether it can do
// what its alg claims. A well-formed RSA key carrying an ECDH alg used to
// reach jwe.Encrypt - after the credential had been issued.
func TestCredentialEncryption_WrongKeyTypeIsRefusedBeforeIssuance(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaJWK, err := jwk.Import(rsaKey.Public())
	require.NoError(t, err)
	require.NoError(t, rsaJWK.Set(jwk.AlgorithmKey, openid4vci.AlgECDHESA256KW))
	rsaEncoded, err := json.Marshal(rsaJWK)
	require.NoError(t, err)

	p384Raw, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384JWK, err := jwk.Import(p384Raw.Public())
	require.NoError(t, err)
	require.NoError(t, p384JWK.Set(jwk.AlgorithmKey, openid4vci.AlgECDHESA256KW))
	p384Encoded, err := json.Marshal(p384JWK)
	require.NoError(t, err)

	for name, encoded := range map[string]json.RawMessage{
		"a valid RSA key claiming an ECDH alg": rsaEncoded,
		"a valid EC key on the wrong curve":    p384Encoded,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEncryptionSetup(t, false, false, false)

			params := e.responseParams(openid4vci.EncA256GCM, "")
			params["jwk"] = encoded

			w := e.post(t, openid4vci.MediaTypeJWT, e.encrypt(t, e.requestBody(t, params), true, false))

			requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
			assert.Zero(t, e.api.calls, "the key is refused before anything is issued")
		})
	}
}

// §7.3.1 has a code that says exactly what is wrong with the encryption
// parameters, and it is not invalid_credential_request. A struct-tag
// "required" on these nested fields would answer an empty
// credential_response_encryption from the generic binder, before any of this
// endpoint's own checks ran.
func TestCredentialEncryption_IncompleteParametersAreAnEncryptionError(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"empty object": {},
		"no jwk":       {"enc": openid4vci.EncA256GCM},
		"no enc":       nil, // filled in below, needs the wallet key
	} {
		t.Run(name, func(t *testing.T) {
			e := newEncryptionSetup(t, false, false, false)
			if params == nil {
				params = map[string]any{"jwk": json.RawMessage(e.walletPub)}
			}

			w := e.post(t, openid4vci.MediaTypeJWT, e.encrypt(t, e.requestBody(t, params), true, false))

			requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
			assert.Zero(t, e.api.calls)
		})
	}
}

// A private EC JWK satisfies jwk.ECDSAPublicKey structurally, so it has to be
// ruled out by name. §8.2 asks for a single PUBLIC key, and an issuer should
// not quietly accept and hold a wallet's private key material.
func TestCredentialEncryption_PrivateKeyIsRefused(t *testing.T) {
	e := newEncryptionSetup(t, false, false, false)

	private, err := json.Marshal(e.walletPriv)
	require.NoError(t, err)
	require.Contains(t, string(private), `"d"`, "this test is pointless unless the JWK carries the private scalar")

	params := e.responseParams(openid4vci.EncA256GCM, "")
	params["jwk"] = json.RawMessage(private)

	w := e.post(t, openid4vci.MediaTypeJWT, e.encrypt(t, e.requestBody(t, params), true, false))

	requireVCIError(t, w, openid4vci.ErrInvalidEncryptionParameters)
	assert.Contains(t, w.Body.String(), "public key")
	assert.Zero(t, e.api.calls)
}
