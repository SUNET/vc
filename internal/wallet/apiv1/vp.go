package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	crypto_sha256 "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// strongSigningAlgorithms lists the only algorithms accepted when verifying
// request-object JWTs.  Weak/symmetric algorithms (HS*, RS256, RS384, RS512)
// are intentionally excluded.
var strongSigningAlgorithms = []string{
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
	"EdDSA",
}

// requestObjectKeyFunc extracts the verification key from the JWT header.
// It supports x5c (X.509 certificate chain) and jwk (embedded JSON Web Key).
func requestObjectKeyFunc(token *jwtv5.Token) (any, error) {
	// Try x5c first – the leaf certificate contains the public key.
	if x5cRaw, ok := token.Header["x5c"]; ok {
		chain, ok := x5cRaw.([]any)
		if !ok || len(chain) == 0 {
			return nil, fmt.Errorf("x5c header present but invalid")
		}
		leafB64, ok := chain[0].(string)
		if !ok {
			return nil, fmt.Errorf("x5c leaf entry is not a string")
		}
		derBytes, err := base64.StdEncoding.DecodeString(leafB64)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c leaf certificate: %w", err)
		}
		cert, err := pki.ParseCertificate(derBytes, nil)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c leaf certificate: %w", err)
		}
		return cert.PublicKey, nil
	}

	// Try jwk – the public key is embedded directly.
	if jwkRaw, ok := token.Header["jwk"]; ok {
		jwkMap, ok := jwkRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("jwk header present but not a JSON object")
		}
		jwkBytes, err := json.Marshal(jwkMap)
		if err != nil {
			return nil, fmt.Errorf("marshaling jwk header: %w", err)
		}
		key, err := jwk.ParseKey(jwkBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing jwk header: %w", err)
		}
		var pubKey any
		if err := jwk.Export(key, &pubKey); err != nil {
			return nil, fmt.Errorf("exporting jwk public key: %w", err)
		}
		// Ensure we return the correct concrete type for the jwt library.
		switch k := pubKey.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported key type from jwk header: %T", k)
		}
	}

	return nil, fmt.Errorf("request object JWT contains neither x5c nor jwk header for signature verification")
}

// runVPScenario executes an OpenID4VP presentation flow
func (c *Client) runVPScenario(ctx context.Context, vp *config.VPScenario, result *ScenarioResult) error {
	// Step 1: Parse the authorization request
	var requestObject *openid4vp.RequestObject

	if vp.AuthorizationRequestURI != "" {
		step := StepResult{Name: "parse_authorization_request", StartedAt: time.Now()}
		var err error
		requestObject, err = c.parseAuthorizationRequestURI(ctx, vp.AuthorizationRequestURI)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			return fmt.Errorf("parsing authorization request URI: %w", err)
		}
		step.Detail = fmt.Sprintf("client_id=%s response_mode=%s", requestObject.ClientID, requestObject.ResponseMode)
		result.Steps = append(result.Steps, step)
	} else if vp.RequestURI != "" {
		step := StepResult{Name: "fetch_request_object", StartedAt: time.Now()}
		var err error
		requestObject, err = c.fetchRequestObject(ctx, vp.RequestURI)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			return fmt.Errorf("fetching request object: %w", err)
		}
		step.Detail = fmt.Sprintf("client_id=%s response_mode=%s nonce=%s", requestObject.ClientID, requestObject.ResponseMode, requestObject.Nonce)
		result.Steps = append(result.Steps, step)
	} else {
		return fmt.Errorf("vp scenario requires either authorization_request_uri or request_uri")
	}

	// Step 2: Select credentials to present
	step := StepResult{Name: "select_credentials", StartedAt: time.Now()}
	selectedCreds, err := c.selectCredentials(ctx, vp, requestObject)
	step.CompletedAt = time.Now()
	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		return fmt.Errorf("selecting credentials: %w", err)
	}
	step.Detail = fmt.Sprintf("selected=%d", len(selectedCreds))
	result.Steps = append(result.Steps, step)

	if len(selectedCreds) == 0 {
		return fmt.Errorf("no matching credentials found in wallet")
	}

	// Step 3: Build VP token
	step = StepResult{Name: "build_vp_token", StartedAt: time.Now()}
	vpToken, err := c.buildVPToken(ctx, selectedCreds, requestObject, vp)
	step.CompletedAt = time.Now()
	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		return fmt.Errorf("building VP token: %w", err)
	}
	txDetail := ""
	if len(requestObject.TransactionData) > 0 {
		txDetail = fmt.Sprintf(" transaction_data_count=%d", len(requestObject.TransactionData))
	}
	step.Detail = fmt.Sprintf("vp_token_length=%d%s", len(vpToken), txDetail)
	result.Steps = append(result.Steps, step)

	// Step 4 Send response (direct_post or redirect)
	step = StepResult{Name: "send_vp_response", StartedAt: time.Now()}
	err = c.sendVPResponse(ctx, requestObject, vpToken, vp)
	step.CompletedAt = time.Now()
	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		return fmt.Errorf("sending VP response: %w", err)
	}
	step.Detail = fmt.Sprintf("response_uri=%s state=%s", requestObject.ResponseURI, requestObject.State)
	result.Steps = append(result.Steps, step)

	return nil
}

// parseAuthorizationRequestURI parses an openid4vp:// or https:// authorization request URI
func (c *Client) parseAuthorizationRequestURI(ctx context.Context, uri string) (*openid4vp.RequestObject, error) {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	q := parsedURL.Query()

	// If there's a request_uri, fetch the request object from it
	requestURI := q.Get("request_uri")
	if requestURI != "" {
		return c.fetchRequestObject(ctx, requestURI)
	}

	// Otherwise parse inline parameters
	ro := &openid4vp.RequestObject{
		ClientID:     q.Get("client_id"),
		ResponseType: q.Get("response_type"),
		ResponseMode: q.Get("response_mode"),
		ResponseURI:  q.Get("response_uri"),
		RedirectURI:  q.Get("redirect_uri"),
		Nonce:        q.Get("nonce"),
		State:        q.Get("state"),
		Scope:        q.Get("scope"),
	}

	return ro, nil
}

// fetchRequestObject fetches and parses a request object JWT from a request_uri
func (c *Client) fetchRequestObject(ctx context.Context, requestURI string) (*openid4vp.RequestObject, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURI, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request object HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Try parsing as JWT first
	bodyStr := strings.TrimSpace(string(body))
	if strings.Count(bodyStr, ".") == 2 {
		// Parse and verify the JWT using only strong signing algorithms
		claims := jwtv5.MapClaims{}
		_, err := jwtv5.NewParser(
			jwtv5.WithValidMethods(strongSigningAlgorithms),
		).ParseWithClaims(bodyStr, claims, requestObjectKeyFunc)
		if err != nil {
			return nil, fmt.Errorf("parsing request object JWT: %w", err)
		}

		// Marshal back to JSON and unmarshal into RequestObject
		claimsJSON, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		var ro openid4vp.RequestObject
		if err := json.Unmarshal(claimsJSON, &ro); err != nil {
			return nil, fmt.Errorf("unmarshaling request object claims: %w", err)
		}
		return &ro, nil
	}

	// Try parsing as plain JSON
	var ro openid4vp.RequestObject
	if err := json.Unmarshal(body, &ro); err != nil {
		return nil, fmt.Errorf("parsing request object JSON: %w", err)
	}
	return &ro, nil
}

// selectCredentials picks credentials from the store based on the VP request and scenario config
func (c *Client) selectCredentials(ctx context.Context, vp *config.VPScenario, ro *openid4vp.RequestObject) ([]string, error) {
	// If explicit credential IDs are specified, use those
	if len(vp.SendCredentialIDs) > 0 {
		var selected []string
		for _, id := range vp.SendCredentialIDs {
			cred, ok := c.store.Get(id)
			if !ok {
				return nil, fmt.Errorf("credential %q not found in store", id)
			}
			selected = append(selected, cred.RawCredential)
		}
		return selected, nil
	}

	// Filter from store
	creds := c.store.List()
	var selected []string

	for _, cred := range creds {
		if vp.CredentialFilter != nil {
			if vp.CredentialFilter.VCT != "" && cred.VCT != vp.CredentialFilter.VCT {
				continue
			}
			if vp.CredentialFilter.Format != "" && cred.Format != vp.CredentialFilter.Format {
				continue
			}
		}
		selected = append(selected, cred.RawCredential)
	}

	// If no filter is set, use all credentials
	if vp.CredentialFilter == nil && len(selected) == 0 {
		for _, cred := range creds {
			selected = append(selected, cred.RawCredential)
		}
	}

	return selected, nil
}

// buildVPToken constructs the VP token from selected credentials
func (c *Client) buildVPToken(ctx context.Context, credentials []string, ro *openid4vp.RequestObject, vp *config.VPScenario) (string, error) {
	// For negative testing: malformed VP
	if vp.MalformedVP {
		return "this-is-not-a-valid-vp-token", nil
	}

	// For SD-JWT based credentials, the VP token is the credential itself
	// with a key binding JWT appended
	if len(credentials) == 1 {
		rawCred := credentials[0]

		// For SD-JWT VCs, append a key binding JWT
		if strings.Contains(rawCred, "~") {
			kbJWT, err := c.createKeyBindingJWT(ctx, ro.Nonce, ro.ClientID, rawCred, ro.TransactionData)
			if err != nil {
				return "", fmt.Errorf("creating key binding JWT: %w", err)
			}

			// If wrong signature requested for negative testing, corrupt it
			if vp.WrongSignature {
				kbJWT = kbJWT[:len(kbJWT)-4] + "XXXX"
			}

			// SD-JWT VP format: credential~disclosure1~disclosure2~...~kb-jwt
			if strings.HasSuffix(rawCred, "~") {
				return rawCred + kbJWT, nil
			}
			return rawCred + "~" + kbJWT, nil
		}

		return rawCred, nil
	}

	// Multiple credentials: wrap in a JSON array
	credsJSON, err := json.Marshal(credentials)
	if err != nil {
		return "", err
	}
	return string(credsJSON), nil
}

// createKeyBindingJWT creates a key binding JWT for SD-JWT presentation
func (c *Client) createKeyBindingJWT(ctx context.Context, nonce, audience, sdJWT string, transactionData []openid4vp.TransactionData) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	signingMethod, alg := jose.GetSigningMethodFromKey(c.signingKey)
	_ = alg

	body := jwtv5.MapClaims{
		"nonce":   nonce,
		"aud":     audience,
		"iat":     time.Now().Unix(),
		"sd_hash": computeSDHash(sdJWT),
	}

	// Include transaction_data_hashes when transaction data is present per OpenID4VP §8.4
	if len(transactionData) > 0 {
		const hashAlg = "sha-256"
		hashes, err := openid4vp.HashTransactionData(transactionData, hashAlg)
		if err != nil {
			return "", fmt.Errorf("hashing transaction data: %w", err)
		}
		body["transaction_data_hashes"] = hashes
		body["transaction_data_hashes_alg"] = hashAlg
		c.log.Info("Including transaction_data_hashes in KB-JWT", "count", len(hashes))
	}

	token := jwtv5.NewWithClaims(signingMethod, body)
	token.Header["typ"] = "kb+jwt"

	signed, err := token.SignedString(c.signingKey)
	if err != nil {
		return "", fmt.Errorf("signing key binding JWT: %w", err)
	}
	return signed, nil
}

func computeSDHash(sdJWT string) string {
	h := crypto_sha256.Sum256([]byte(sdJWT))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// sendVPResponse sends the VP token to the verifier
func (c *Client) sendVPResponse(ctx context.Context, ro *openid4vp.RequestObject, vpToken string, vp *config.VPScenario) error {
	responseURI := ro.ResponseURI
	if responseURI == "" {
		responseURI = ro.RedirectURI
	}
	if responseURI == "" {
		return fmt.Errorf("no response_uri or redirect_uri in request object")
	}

	responseMode := ro.ResponseMode
	if vp.ResponseMode != "" {
		responseMode = vp.ResponseMode
	}

	switch responseMode {
	case "direct_post", "":
		return c.sendDirectPost(ctx, responseURI, vpToken, ro.State)
	case "direct_post.jwt":
		// For now, send as direct_post (JWT encryption would be added here)
		c.log.Warn("direct_post.jwt response mode requested, sending as plain direct_post")
		return c.sendDirectPost(ctx, responseURI, vpToken, ro.State)
	default:
		return fmt.Errorf("unsupported response_mode: %s", responseMode)
	}
}

func (c *Client) sendDirectPost(ctx context.Context, responseURI, vpToken, state string) error {
	data := url.Values{
		"vp_token": {vpToken},
	}
	if state != "" {
		data.Set("state", state)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURI, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("direct_post HTTP %d: %s", resp.StatusCode, string(body))
	}

	c.log.Info("VP response sent successfully", "response_uri", responseURI, "status", resp.StatusCode)
	return nil
}
