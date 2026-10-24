//go:build integration

package integration

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/testsupport/jwktest"
	"github.com/SUNET/vc/pkg/testsupport/walletflow"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/fxamacker/cbor/v2"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nymAuthNamespace = "eu.europa.ec.eudi.nym_auth.1"

// issuePID issues a PID of scope pid or pid_mdoc to a fresh holder key
// through the mock OIDC login, and returns it with the key.
func issuePID(t *testing.T, scope string, claims map[string]string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)
	meta := fetchIssuerMetadata(t, apigwURL)
	codeVerifier := uuid.New().String() + uuid.New().String()
	parResp := doPAR(t, oauth2Meta.PAREndpoint, url.Values{
		"response_type": {"code"}, "client_id": {oauthClientID}, "redirect_uri": {oauthRedirect},
		"state": {uuid.New().String()}, "code_challenge": {walletflow.ComputeS256(codeVerifier)},
		"code_challenge_method": {"S256"}, "scope": {scope},
	})
	code := doConsentFlow(t, oauth2Meta.AuthorizationEndpoint, parResp.RequestURI, oauthClientID, claims)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	token := doTokenRequest(t, rewritePublicToInternal(oauth2Meta.TokenEndpoint), code, codeVerifier, key)

	proof := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, jwtv5.MapClaims{
		"aud": meta.CredentialIssuer, "iat": time.Now().Unix(), "nonce": token.CNonce,
	})
	proof.Header["typ"] = "openid4vci-proof+jwt"
	proof.Header["jwk"] = jwktest.PublicKeyJWK(&key.PublicKey)
	signedProof, err := proof.SignedString(key)
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{"credential_configuration_id": scope, "proofs": map[string]any{"jwt": []string{signedProof}}})
	require.NoError(t, err)
	credEndpoint := rewritePublicToInternal(meta.CredentialEndpoint)
	req, err := http.NewRequest(http.MethodPost, credEndpoint, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", walletflow.DPoPProof(t, http.MethodPost, rewriteInternalToPublic(credEndpoint), token.AccessToken, key))
	req.Header.Set("Authorization", "DPoP "+token.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s credential: %s", scope, raw)
	var credResp openid4vci.CredentialResponse
	require.NoError(t, json.Unmarshal(raw, &credResp))
	require.Len(t, credResp.Credentials, 1)
	return credResp.Credentials[0].Credential, key
}

// requestObject is what the test wallet reads from the signed OpenID4VP
// request object.
type requestObject struct {
	ClientID       string `json:"client_id"`
	Nonce          string `json:"nonce"`
	State          string `json:"state"`
	ResponseURI    string `json:"response_uri"`
	ClientMetadata struct {
		JWKS struct {
			Keys []json.RawMessage `json:"keys"`
		} `json:"jwks"`
	} `json:"client_metadata"`
}

// nymAuthAccess runs PAR for nym_auth, answers the OpenID4VP request with
// the PID of presentedScope, and returns the token response for a fresh
// proof key.
func nymAuthAccess(t *testing.T, presentedScope, pid string, pidKey *ecdsa.PrivateKey) (openid4vci.TokenResponse, *ecdsa.PrivateKey) {
	t.Helper()
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)
	codeVerifier := uuid.New().String() + uuid.New().String()
	parResp := doPAR(t, oauth2Meta.PAREndpoint, url.Values{
		"response_type": {"code"}, "client_id": {oauthClientID}, "redirect_uri": {oauthRedirect},
		"state": {uuid.New().String()}, "code_challenge": {walletflow.ComputeS256(codeVerifier)},
		"code_challenge_method": {"S256"}, "scope": {"nym_auth"},
	})

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	browser := &http.Client{Transport: tlsTransport, Jar: jar, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(target string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, rewritePublicToInternal(target), nil)
		require.NoError(t, err)
		req.Header.Set("Accept", "application/json")
		resp, err := browser.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp
	}

	// /authorize and /authorization/consent, headless, end at the wallet
	// with the OpenID4VP request_uri.
	walletURL, err := url.Parse(fmt.Sprintf("%s?client_id=%s&request_uri=%s", oauth2Meta.AuthorizationEndpoint,
		url.QueryEscape(oauthClientID), url.QueryEscape(parResp.RequestURI)))
	require.NoError(t, err)
	for i := 0; i < 5 && !strings.Contains(walletURL.Query().Get("request_uri"), "/verification/request-object"); i++ {
		resp := get(walletURL.String())
		require.Equal(t, http.StatusFound, resp.StatusCode, "redirect from %s", walletURL)
		walletURL, err = resp.Request.URL.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
	}
	require.Contains(t, walletURL.Query().Get("request_uri"), "/verification/request-object", "headless consent ends at the wallet: %s", walletURL)

	resp, err := tlsClient().Get(rewritePublicToInternal(walletURL.Query().Get("request_uri")))
	require.NoError(t, err)
	signed, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "request object: %s", signed)
	var ro requestObject
	require.NoError(t, jwtPayload(strings.TrimSpace(string(signed)), &ro))
	require.Len(t, ro.ClientMetadata.JWKS.Keys, 1)
	readerKey, err := jwk.ParseKey(ro.ClientMetadata.JWKS.Keys[0])
	require.NoError(t, err)

	var presentation string
	switch presentedScope {
	case "pid":
		sdJWT := pid
		if !strings.HasSuffix(sdJWT, "~") {
			sdJWT += "~"
		}
		presentation = sdJWT + createKeyBindingJWT(t, ro.Nonce, ro.ClientID, sdJWT, pidKey)
	case "pid_mdoc":
		raw, err := base64.RawURLEncoding.DecodeString(pid)
		require.NoError(t, err)
		issued, err := mdoc.DecodeDeviceResponse(raw)
		require.NoError(t, err)
		require.Len(t, issued.Documents, 1)
		thumbprint, err := readerKey.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		transcript, err := mdoc.BuildOID4VPSessionTranscript(ro.ClientID, ro.Nonce, ro.ResponseURI, thumbprint)
		require.NoError(t, err)
		response, err := mdoc.NewDeviceResponseBuilder(issued.Documents[0].DocType).
			WithIssuerSigned(&issued.Documents[0].IssuerSigned).
			WithDeviceKey(pidKey).
			WithSessionTranscript(transcript).
			Build()
		require.NoError(t, err)
		encoded, err := mdoc.EncodeDeviceResponse(response)
		require.NoError(t, err)
		presentation = base64.RawURLEncoding.EncodeToString(encoded)
	default:
		t.Fatalf("no presentation for %q", presentedScope)
	}

	payload, err := json.Marshal(map[string]any{"vp_token": map[string][]string{presentedScope: {presentation}}, "state": ro.State})
	require.NoError(t, err)
	kid, ok := readerKey.KeyID()
	require.True(t, ok)
	headers := jwe.NewHeaders()
	require.NoError(t, headers.Set(jwe.KeyIDKey, kid))
	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.ECDH_ES(), readerKey), jwe.WithContentEncryption(jwa.A256GCM()), jwe.WithProtectedHeaders(headers))
	require.NoError(t, err)

	resp, err = tlsClient().PostForm(rewritePublicToInternal(ro.ResponseURI), url.Values{"response": {string(encrypted)}})
	require.NoError(t, err)
	posted, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "direct_post: %s", posted)
	var directPost struct {
		RedirectURI string `json:"redirect_uri"`
	}
	require.NoError(t, json.Unmarshal(posted, &directPost))

	callback := get(directPost.RedirectURI)
	for i := 0; i < 3 && callback.StatusCode == http.StatusMovedPermanently; i++ {
		next, err := callback.Request.URL.Parse(callback.Header.Get("Location"))
		require.NoError(t, err)
		callback = get(next.String())
	}
	require.Equal(t, http.StatusFound, callback.StatusCode, "headless consent")
	codeURL, err := url.Parse(callback.Header.Get("Location"))
	require.NoError(t, err)
	code := codeURL.Query().Get("code")
	require.NotEmpty(t, code, "consent redirect: %s", codeURL)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return doTokenRequest(t, rewritePublicToInternal(oauth2Meta.TokenEndpoint), code, codeVerifier, key), key
}

func tlsClient() *http.Client {
	return &http.Client{Transport: tlsTransport, Timeout: 15 * time.Second}
}

func jwtPayload(token string, v any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("a compact JWT has 3 parts, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func pscEntry(psc []byte) []any {
	return []any{map[string]any{
		"type": "hash_commitment", "alg": "sha-256", "path": []string{nymAuthNamespace, "psc"},
		"commitment": base64.RawURLEncoding.EncodeToString(psc),
	}}
}

// nymAuthCredentialRequest sends a credential request whose proof carries
// psc when psc is set. With tamper, the signed payload is replaced by one
// carrying a different psc. With encrypt, the request is a JWE to the
// issuer's key and asks for an encrypted response; the decrypted response
// is returned.
func nymAuthCredentialRequest(t *testing.T, meta *openid4vci.CredentialIssuerMetadataParameters, token openid4vci.TokenResponse, key *ecdsa.PrivateKey, psc []byte, tamper, encrypt bool) (int, []byte) {
	t.Helper()
	proofClaims := jwtv5.MapClaims{"aud": meta.CredentialIssuer, "iat": time.Now().Unix(), "nonce": token.CNonce}
	if psc != nil {
		proofClaims["auxiliary_data"] = pscEntry(psc)
	}
	proof := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, proofClaims)
	proof.Header["typ"] = "openid4vci-proof+jwt"
	proof.Header["jwk"] = jwktest.PublicKeyJWK(&key.PublicKey)
	signedProof, err := proof.SignedString(key)
	require.NoError(t, err)
	if tamper {
		other := sha256.Sum256([]byte("someone else's seed"))
		proofClaims["auxiliary_data"] = pscEntry(other[:])
		payload, err := json.Marshal(proofClaims)
		require.NoError(t, err)
		parts := strings.Split(signedProof, ".")
		signedProof = parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]
	}

	body := map[string]any{
		"credential_configuration_id": "nym_auth",
		"proofs":                      map[string]any{"jwt": []string{signedProof}},
	}
	contentType := "application/json"
	var responseKey *ecdsa.PrivateKey
	var payload []byte
	if encrypt {
		responseKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		responseJWK, err := jwk.Import(&responseKey.PublicKey)
		require.NoError(t, err)
		require.NoError(t, responseJWK.Set(jwk.AlgorithmKey, jwa.ECDH_ES_A256KW()))
		body["credential_response_encryption"] = map[string]any{"jwk": responseJWK, "enc": "A256GCM"}

		requestKeys, err := jwk.Parse(meta.CredentialRequestEncryption.JWKS)
		require.NoError(t, err)
		requestKey, ok := requestKeys.Key(0)
		require.True(t, ok)
		kid, ok := requestKey.KeyID()
		require.True(t, ok)
		headers := jwe.NewHeaders()
		require.NoError(t, headers.Set(jwe.KeyIDKey, kid))
		plain, err := json.Marshal(body)
		require.NoError(t, err)
		payload, err = jwe.Encrypt(plain, jwe.WithKey(jwa.ECDH_ES_A256KW(), requestKey), jwe.WithContentEncryption(jwa.A256GCM()), jwe.WithProtectedHeaders(headers))
		require.NoError(t, err)
		contentType = openid4vci.MediaTypeJWT
	} else {
		payload, err = json.Marshal(body)
		require.NoError(t, err)
	}

	credEndpoint := rewritePublicToInternal(meta.CredentialEndpoint)
	req, err := http.NewRequest(http.MethodPost, credEndpoint, bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("DPoP", walletflow.DPoPProof(t, http.MethodPost, rewriteInternalToPublic(credEndpoint), token.AccessToken, key))
	req.Header.Set("Authorization", "DPoP "+token.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.StatusCode == http.StatusOK && encrypt {
		require.Equal(t, openid4vci.MediaTypeJWT, resp.Header.Get("Content-Type"))
		raw, err = jwe.Decrypt(bytes.TrimSpace(raw), jwe.WithKey(jwa.ECDH_ES_A256KW(), responseKey))
		require.NoError(t, err)
	}
	return resp.StatusCode, raw
}

// issuerSignedElements verifies the MSO signature of an issued mso_mdoc
// credential and the digest of every element, and returns the verified
// elements of the nym_auth namespace. Trust in the dev chain is assumed.
func issuerSignedElements(t *testing.T, credential string) (string, map[string]any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(credential)
	require.NoError(t, err)
	response, err := mdoc.DecodeDeviceResponse(raw)
	require.NoError(t, err)
	require.Len(t, response.Documents, 1)
	document := response.Documents[0]

	verifier, err := mdoc.NewVerifier(mdoc.VerifierConfig{
		TrustEvaluator:      &trust.AllowAllEvaluator{},
		SkipRevocationCheck: true,
	})
	require.NoError(t, err)
	_, verified, err := verifier.VerifyIssuerSigned(&document.IssuerSigned, document.DocType)
	require.NoError(t, err, "the issuer signature must cover every element")
	return document.DocType, verified[nymAuthNamespace]
}

func TestStack_NymAuth(t *testing.T) {
	meta := fetchIssuerMetadata(t, apigwURL)
	config, ok := meta.CredentialConfigurationsSupported["nym_auth"]
	require.True(t, ok, "nym_auth is offered")
	announced, err := json.Marshal(config.AuxiliaryDataSupported)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"to_wallet": [{"type": "hash_commitment", "alg": "sha-256", "path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"]}],
		"to_issuer": [{"type": "hash_commitment", "alg": "sha-256", "path": ["eu.europa.ec.eudi.nym_auth.1", "psc"]}]}`, string(announced))
	require.NotNil(t, meta.CredentialRequestEncryption, "the issuer publishes its request encryption key")

	openings := map[string]string{}
	for _, person := range []struct {
		name   string
		claims map[string]string
	}{
		{"adult", map[string]string{"given_name": "Helen", "family_name": "Mirren", "birth_date": "1996-01-30"}},
		{"teen", map[string]string{"given_name": "Alex", "family_name": "Young", "birth_date": "2011-06-15"}},
	} {
		for _, presented := range []string{"pid", "pid_mdoc"} {
			t.Run(person.name+"/"+presented, func(t *testing.T) {
				pid, pidKey := issuePID(t, presented, person.claims)
				psc := sha256.Sum256([]byte("private seed of " + person.name))
				issue := func(psc []byte, tamper, encrypt bool) (int, []byte) {
					token, key := nymAuthAccess(t, presented, pid, pidKey)
					return nymAuthCredentialRequest(t, meta, token, key, psc, tamper, encrypt)
				}

				status, body := issue(psc[:], false, false)
				assert.Equal(t, http.StatusBadRequest, status)
				assert.True(t, strings.Contains(string(body), "invalid_encryption_parameters"), "got: %s", body)

				status, body = issue(psc[:], true, true)
				assert.Equal(t, http.StatusBadRequest, status, "a psc changed after signing: %s", body)
				assert.True(t, strings.Contains(string(body), "invalid_proof"), "got: %s", body)

				for _, withPSC := range []bool{true, false} {
					var sent []byte
					if withPSC {
						sent = psc[:]
					}
					status, body = issue(sent, false, true)
					require.Equal(t, http.StatusOK, status, "credential: %s", body)
					var response openid4vci.CredentialResponse
					require.NoError(t, json.Unmarshal(body, &response))
					require.Len(t, response.Credentials, 1)
					require.NotNil(t, response.CredentialMetadata)
					require.Len(t, response.CredentialMetadata.AuxiliaryData, 1)
					entry := response.CredentialMetadata.AuxiliaryData[0]
					assert.Equal(t, []string{nymAuthNamespace, "ssc"}, entry.Path)
					opening, err := base64.RawURLEncoding.DecodeString(entry.Opening)
					require.NoError(t, err)
					require.Len(t, opening, 16)
					if previous, ok := openings[person.name]; ok {
						assert.Equal(t, previous, entry.Opening, "one person, one opening, whichever PID they present")
					}
					openings[person.name] = entry.Opening

					docType, elements := issuerSignedElements(t, response.Credentials[0].Credential)
					assert.Equal(t, nymAuthNamespace, docType)
					ssc := sha256.Sum256(opening)
					assert.Equal(t, ssc[:], elements["ssc"], "the opening opens the issued ssc")
					if withPSC {
						assert.Equal(t, psc[:], elements["psc"], "the issued psc is the wallet's")
					} else {
						assert.NotContains(t, elements, "psc")
					}
					birthDate, ok := elements["birth_date"].(cbor.Tag)
					require.True(t, ok, "birth_date is %T", elements["birth_date"])
					assert.Equal(t, person.claims["birth_date"], birthDate.Content)
					t.Logf("%s from %s, psc=%v: birth_date=%v ssc=%x psc=%x elements=%v", person.name, presented, withPSC, birthDate.Content, elements["ssc"], elements["psc"], len(elements))
				}

				// One psc per person: another wallet's psc is refused until
				// an operator resets the recorded one.
				other := sha256.Sum256([]byte("another wallet of " + person.name))
				status, body = issue(other[:], false, true)
				t.Logf("CONFLICT %s/%s: HTTP %d %s", person.name, presented, status, body)
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Contains(t, string(body), "auxiliary_data_conflict")
			})
		}
	}
	assert.NotEqual(t, openings["adult"], openings["teen"], "two people, two openings")
}

// TestStack_NymAuthAfterReset: after an operator reset Helen Mirren's
// commitment, her other wallet's psc is accepted and issued.
func TestStack_NymAuthAfterReset(t *testing.T) {
	meta := fetchIssuerMetadata(t, apigwURL)
	claims := map[string]string{"given_name": "Helen", "family_name": "Mirren", "birth_date": "1996-01-30"}
	pid, pidKey := issuePID(t, "pid", claims)
	other := sha256.Sum256([]byte("another wallet of adult"))
	token, key := nymAuthAccess(t, "pid", pid, pidKey)
	status, body := nymAuthCredentialRequest(t, meta, token, key, other[:], false, true)
	require.Equal(t, http.StatusOK, status, "credential: %s", body)
	var response openid4vci.CredentialResponse
	require.NoError(t, json.Unmarshal(body, &response))
	_, elements := issuerSignedElements(t, response.Credentials[0].Credential)
	assert.Equal(t, other[:], elements["psc"], "the new wallet's psc is issued")
	t.Logf("AFTER RESET: psc=%x", elements["psc"])
}
