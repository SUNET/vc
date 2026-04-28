package apiv1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/internal/wallet/credential"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/openid4vci"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Client is the wallet's business logic layer
type Client struct {
	cfg        *config.Config
	store      *credential.Store
	log        *slog.Logger
	httpClient *http.Client
	signingKey crypto.PrivateKey
	results    *ResultStore
}

// New creates a new wallet client
func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Client, error) {
	c := &Client{
		cfg:   cfg,
		store: credential.NewStore(),
		log:   log.With("component", "apiv1"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		results: NewResultStore(),
	}

	// Load or generate signing key
	if cfg.Wallet.KeyPath != "" {
		key, err := jose.ParseSigningKey(cfg.Wallet.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading wallet key: %w", err)
		}
		c.signingKey = key
	} else {
		// Generate an ephemeral EC P-256 key for testing
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ephemeral key: %w", err)
		}
		c.signingKey = key
		c.log.Info("generated ephemeral EC P-256 signing key (no key_path configured)")
	}

	return c, nil
}

// Store returns the credential store
func (c *Client) Store() *credential.Store {
	return c.store
}

// Results returns the result store
func (c *Client) Results() *ResultStore {
	return c.results
}

// RunScenario executes a single scenario by name
func (c *Client) RunScenario(ctx context.Context, name string) (*ScenarioResult, error) {
	for _, s := range c.cfg.Scenarios {
		if s.Name == name {
			return c.executeScenario(ctx, &s)
		}
	}
	return nil, fmt.Errorf("scenario %q not found", name)
}

// RunAllAutoScenarios runs all scenarios marked as auto_run
func (c *Client) RunAllAutoScenarios(ctx context.Context) {
	for _, s := range c.cfg.Scenarios {
		if !s.AutoRun {
			continue
		}
		go func(scenario config.Scenario) {
			if scenario.DelayBefore > 0 {
				c.log.Info("waiting before scenario", "scenario", scenario.Name, "delay", scenario.DelayBefore)
				time.Sleep(scenario.DelayBefore)
			}
			result, err := c.executeScenario(ctx, &scenario)
			if err != nil {
				c.log.Error("auto-run scenario failed", "scenario", scenario.Name, "error", err)
				return
			}
			c.log.Info("auto-run scenario completed", "scenario", scenario.Name, "success", result.Success)
		}(s)
	}
}

func (c *Client) executeScenario(ctx context.Context, scenario *config.Scenario) (*ScenarioResult, error) {
	c.log.Info("executing scenario", "name", scenario.Name, "type", scenario.Type)

	result := &ScenarioResult{
		ScenarioName: scenario.Name,
		Type:         scenario.Type,
		StartedAt:    time.Now(),
		Steps:        []StepResult{},
	}

	var err error
	switch scenario.Type {
	case "vci":
		if scenario.VCI == nil {
			err = fmt.Errorf("scenario %q is type=vci but has no vci config", scenario.Name)
		} else {
			err = c.runVCIScenario(ctx, scenario.VCI, result)
		}
	case "vp":
		if scenario.VP == nil {
			err = fmt.Errorf("scenario %q is type=vp but has no vp config", scenario.Name)
		} else {
			err = c.runVPScenario(ctx, scenario.VP, result)
		}
	default:
		err = fmt.Errorf("unknown scenario type %q", scenario.Type)
	}

	result.CompletedAt = time.Now()
	if err != nil {
		result.Error = err.Error()
		result.Success = false
		// Check if this was an expected error
		expectedErr := ""
		if scenario.VCI != nil {
			expectedErr = scenario.VCI.ExpectError
		} else if scenario.VP != nil {
			expectedErr = scenario.VP.ExpectError
		}
		if expectedErr != "" && strings.Contains(err.Error(), expectedErr) {
			result.Success = true
			result.Error = fmt.Sprintf("expected error matched: %s", err.Error())
		}
	} else {
		result.Success = true
	}

	c.results.Add(result)
	return result, nil
}

// runVCIScenario executes an OpenID4VCI credential issuance flow
func (c *Client) runVCIScenario(ctx context.Context, vci *config.VCIScenario, result *ScenarioResult) error {
	// Step 1: Resolve credential offer or metadata
	var issuerURL string
	var credentialConfigID string

	if vci.CredentialOfferURI != "" {
		step := StepResult{Name: "fetch_credential_offer", StartedAt: time.Now()}
		offerParams, err := c.fetchCredentialOffer(ctx, vci.CredentialOfferURI)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			return fmt.Errorf("fetching credential offer: %w", err)
		}
		step.Detail = fmt.Sprintf("issuer=%s configs=%v", offerParams.CredentialIssuer, offerParams.CredentialConfigurationIDs)
		result.Steps = append(result.Steps, step)

		issuerURL = offerParams.CredentialIssuer
		if len(offerParams.CredentialConfigurationIDs) > 0 {
			credentialConfigID = offerParams.CredentialConfigurationIDs[0]
		}

		// Check for pre-authorized code in grants
		if grants, ok := offerParams.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]; ok {
			if grantMap, ok := grants.(map[string]any); ok {
				if code, ok := grantMap["pre-authorized_code"].(string); ok {
					vci.PreAuthorizedCode = code
				}
			}
		}
	} else if vci.CredentialOffer != "" {
		step := StepResult{Name: "parse_credential_offer", StartedAt: time.Now()}
		var offerParams openid4vci.CredentialOfferParameters
		if err := json.Unmarshal([]byte(vci.CredentialOffer), &offerParams); err != nil {
			step.Error = err.Error()
			step.CompletedAt = time.Now()
			result.Steps = append(result.Steps, step)
			return fmt.Errorf("parsing credential offer: %w", err)
		}
		step.CompletedAt = time.Now()
		result.Steps = append(result.Steps, step)
		issuerURL = offerParams.CredentialIssuer
		if len(offerParams.CredentialConfigurationIDs) > 0 {
			credentialConfigID = offerParams.CredentialConfigurationIDs[0]
		}
	} else {
		issuerURL = vci.IssuerURL
		credentialConfigID = vci.CredentialConfigurationID
	}

	if issuerURL == "" {
		return fmt.Errorf("no issuer URL resolved")
	}

	// Override credential config ID from scenario if set
	if vci.CredentialConfigurationID != "" {
		credentialConfigID = vci.CredentialConfigurationID
	}

	// Step 2: Fetch issuer metadata
	step := StepResult{Name: "fetch_issuer_metadata", StartedAt: time.Now()}
	metadata, err := c.fetchIssuerMetadata(ctx, issuerURL)
	step.CompletedAt = time.Now()
	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		return fmt.Errorf("fetching issuer metadata: %w", err)
	}
	step.Detail = fmt.Sprintf("credential_endpoint=%s configs=%d", metadata.CredentialEndpoint, len(metadata.CredentialConfigurationsSupported))
	result.Steps = append(result.Steps, step)

	// Step 3: Fetch OAuth2 authorization server metadata
	step = StepResult{Name: "fetch_oauth2_metadata", StartedAt: time.Now()}
	authServerURL := issuerURL
	if len(metadata.AuthorizationServers) > 0 {
		authServerURL = metadata.AuthorizationServers[0]
	}
	oauth2Meta, err := c.fetchOAuth2Metadata(ctx, authServerURL)
	step.CompletedAt = time.Now()
	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		return fmt.Errorf("fetching oauth2 metadata: %w", err)
	}
	step.Detail = fmt.Sprintf("token_endpoint=%s", oauth2Meta.TokenEndpoint)
	result.Steps = append(result.Steps, step)

	// Step 4: Get a nonce if the issuer supports it
	var cNonce string
	if metadata.CredentialEndpoint != "" {
		step = StepResult{Name: "fetch_nonce", StartedAt: time.Now()}
		nonceResp, err := c.fetchNonce(ctx, issuerURL)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = fmt.Sprintf("nonce fetch failed (optional): %s", err.Error())
			c.log.Warn("nonce endpoint not available, continuing", "error", err)
		} else {
			cNonce = nonceResp.CNonce
			step.Detail = fmt.Sprintf("c_nonce=%s", cNonce)
		}
		result.Steps = append(result.Steps, step)
	}

	// Step 5: Token request
	var accessToken string
	var tokenType string

	if vci.PreAuthorizedCode != "" {
		step = StepResult{Name: "token_request_pre_auth", StartedAt: time.Now()}
		tokenResp, err := c.tokenRequestPreAuth(ctx, oauth2Meta.TokenEndpoint, vci)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			return fmt.Errorf("pre-auth token request: %w", err)
		}
		accessToken = tokenResp.AccessToken
		tokenType = tokenResp.TokenType
		if tokenResp.CNonce != "" {
			cNonce = tokenResp.CNonce
		}
		step.Detail = fmt.Sprintf("token_type=%s c_nonce=%s", tokenType, cNonce)
		result.Steps = append(result.Steps, step)
	} else {
		// Authorization code flow
		step = StepResult{Name: "authorization", StartedAt: time.Now()}
		authCode, err := c.doAuthorization(ctx, oauth2Meta, vci, credentialConfigID)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			return fmt.Errorf("authorization: %w", err)
		}
		step.Detail = fmt.Sprintf("code=%s", authCode)
		result.Steps = append(result.Steps, step)

		step = StepResult{Name: "token_request_auth_code", StartedAt: time.Now()}
		tokenResp, err := c.tokenRequestAuthCode(ctx, oauth2Meta.TokenEndpoint, authCode, vci)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			return fmt.Errorf("auth code token request: %w", err)
		}
		accessToken = tokenResp.AccessToken
		tokenType = tokenResp.TokenType
		if tokenResp.CNonce != "" {
			cNonce = tokenResp.CNonce
		}
		step.Detail = fmt.Sprintf("token_type=%s c_nonce=%s", tokenType, cNonce)
		result.Steps = append(result.Steps, step)
	}

	// Step 6: Credential request
	step = StepResult{Name: "credential_request", StartedAt: time.Now()}
	credResp, err := c.requestCredential(ctx, metadata.CredentialEndpoint, accessToken, tokenType, cNonce, credentialConfigID, vci)
	step.CompletedAt = time.Now()
	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		return fmt.Errorf("credential request: %w", err)
	}
	result.Steps = append(result.Steps, step)

	// Handle deferred issuance
	if credResp.TransactionID != "" && vci.DeferredPolling {
		step = StepResult{Name: "deferred_credential", StartedAt: time.Now()}
		credResp, err = c.pollDeferredCredential(ctx, metadata.DeferredCredentialEndpoint, accessToken, tokenType, credResp.TransactionID, vci)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			return fmt.Errorf("deferred credential: %w", err)
		}
		result.Steps = append(result.Steps, step)
	}

	// Step 7: Store credentials
	for _, cred := range credResp.Credentials {
		stored := &credential.StoredCredential{
			RawCredential:  cred.Credential,
			Format:         c.detectFormat(cred.Credential),
			IssuerURL:      issuerURL,
			ScenarioName:   result.ScenarioName,
			NotificationID: credResp.NotificationID,
		}
		id := c.store.Add(stored)
		c.log.Info("credential stored", "id", id, "format", stored.Format, "issuer", issuerURL)
	}

	step.Detail = fmt.Sprintf("credentials_received=%d", len(credResp.Credentials))

	// Step 8: Notification (optional)
	if vci.SendNotification && credResp.NotificationID != "" && metadata.NotificationEndpoint != "" {
		step = StepResult{Name: "notification", StartedAt: time.Now()}
		event := vci.NotificationEvent
		if event == "" {
			event = "credential_accepted"
		}
		err := c.sendNotification(ctx, metadata.NotificationEndpoint, accessToken, tokenType, credResp.NotificationID, event)
		step.CompletedAt = time.Now()
		if err != nil {
			step.Error = err.Error()
		}
		step.Detail = fmt.Sprintf("event=%s notification_id=%s", event, credResp.NotificationID)
		result.Steps = append(result.Steps, step)
	}

	return nil
}

// ---------- VCI helper methods ----------

func (c *Client) fetchCredentialOffer(ctx context.Context, offerURI string) (*openid4vci.CredentialOfferParameters, error) {
	resp, err := c.httpClient.Get(offerURI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("credential offer HTTP %d: %s", resp.StatusCode, string(body))
	}

	var offer openid4vci.CredentialOfferParameters
	if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
		return nil, err
	}
	return &offer, nil
}

func (c *Client) fetchIssuerMetadata(ctx context.Context, issuerURL string) (*openid4vci.CredentialIssuerMetadataParameters, error) {
	metaURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-credential-issuer"
	resp, err := c.httpClient.Get(metaURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("issuer metadata HTTP %d: %s", resp.StatusCode, string(body))
	}

	var meta openid4vci.CredentialIssuerMetadataParameters
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

type oauth2ServerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	PAREndpoint           string `json:"pushed_authorization_request_endpoint"`
	NonceEndpoint         string `json:"nonce_endpoint"`
}

func (c *Client) fetchOAuth2Metadata(ctx context.Context, serverURL string) (*oauth2ServerMetadata, error) {
	metaURL := strings.TrimRight(serverURL, "/") + "/.well-known/oauth-authorization-server"
	resp, err := c.httpClient.Get(metaURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("oauth2 metadata HTTP %d: %s", resp.StatusCode, string(body))
	}

	var meta oauth2ServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func (c *Client) fetchNonce(ctx context.Context, issuerURL string) (*openid4vci.NonceResponse, error) {
	nonceURL := strings.TrimRight(issuerURL, "/") + "/nonce"
	resp, err := c.httpClient.Post(nonceURL, "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("nonce HTTP %d: %s", resp.StatusCode, string(body))
	}

	var nonceResp openid4vci.NonceResponse
	if err := json.NewDecoder(resp.Body).Decode(&nonceResp); err != nil {
		return nil, err
	}
	return &nonceResp, nil
}

func (c *Client) tokenRequestPreAuth(ctx context.Context, tokenEndpoint string, vci *config.VCIScenario) (*openid4vci.TokenResponse, error) {
	data := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {vci.PreAuthorizedCode},
	}
	if vci.TXCode != "" {
		data.Set("tx_code", vci.TXCode)
	}
	if c.cfg.Wallet.ClientID != "" {
		data.Set("client_id", c.cfg.Wallet.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if vci.UseDPoP {
		dpopToken, err := c.createDPoPProof(http.MethodPost, tokenEndpoint, "")
		if err != nil {
			return nil, fmt.Errorf("creating DPoP proof: %w", err)
		}
		req.Header.Set("DPoP", dpopToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp openid4vci.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

func (c *Client) doAuthorization(ctx context.Context, oauth2Meta *oauth2ServerMetadata, vci *config.VCIScenario, credentialConfigID string) (string, error) {
	codeVerifier := uuid.New().String() + uuid.New().String()
	codeChallenge := computeS256Challenge(codeVerifier)

	state := uuid.New().String()
	redirectURI := vci.RedirectURI
	if redirectURI == "" {
		redirectURI = "http://localhost:8080/callback"
	}

	if vci.UsePAR && oauth2Meta.PAREndpoint != "" {
		parData := url.Values{
			"response_type":         {"code"},
			"client_id":             {c.cfg.Wallet.ClientID},
			"redirect_uri":          {redirectURI},
			"state":                 {state},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
		}
		if vci.Scope != "" {
			parData.Set("scope", vci.Scope)
		}
		if credentialConfigID != "" {
			authDetails := []openid4vci.AuthorizationDetailsParameter{{
				Type:                      "openid_credential",
				CredentialConfigurationID: credentialConfigID,
			}}
			authDetailsJSON, _ := json.Marshal(authDetails)
			parData.Set("authorization_details", string(authDetailsJSON))
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauth2Meta.PAREndpoint, strings.NewReader(parData.Encode()))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("PAR HTTP %d: %s", resp.StatusCode, string(body))
		}

		var parResp openid4vci.ParResponse
		if err := json.NewDecoder(resp.Body).Decode(&parResp); err != nil {
			return "", err
		}

		authURL := fmt.Sprintf("%s?client_id=%s&request_uri=%s",
			oauth2Meta.AuthorizationEndpoint,
			url.QueryEscape(c.cfg.Wallet.ClientID),
			url.QueryEscape(parResp.RequestURI))

		return c.followAuthorization(ctx, authURL)
	}

	// Standard authorization request
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.cfg.Wallet.ClientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	if vci.Scope != "" {
		params.Set("scope", vci.Scope)
	}
	authURL := fmt.Sprintf("%s?%s", oauth2Meta.AuthorizationEndpoint, params.Encode())
	return c.followAuthorization(ctx, authURL)
}

func (c *Client) followAuthorization(ctx context.Context, authURL string) (string, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(authURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		location := resp.Header.Get("Location")
		if location != "" {
			redirectURL, err := url.Parse(location)
			if err != nil {
				return "", fmt.Errorf("parsing redirect URL: %w", err)
			}
			code := redirectURL.Query().Get("code")
			if code != "" {
				return code, nil
			}
			return "", fmt.Errorf("no code in redirect: %s", location)
		}
	}

	body, _ := io.ReadAll(resp.Body)
	return "", fmt.Errorf("authorization did not redirect (HTTP %d): %s", resp.StatusCode, string(body))
}

func (c *Client) tokenRequestAuthCode(ctx context.Context, tokenEndpoint, code string, vci *config.VCIScenario) (*openid4vci.TokenResponse, error) {
	redirectURI := vci.RedirectURI
	if redirectURI == "" {
		redirectURI = "http://localhost:8080/callback"
	}

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {c.cfg.Wallet.ClientID},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if vci.UseDPoP {
		dpopToken, err := c.createDPoPProof(http.MethodPost, tokenEndpoint, "")
		if err != nil {
			return nil, fmt.Errorf("creating DPoP proof: %w", err)
		}
		req.Header.Set("DPoP", dpopToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp openid4vci.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

func (c *Client) requestCredential(ctx context.Context, credentialEndpoint, accessToken, tokenType, cNonce, credentialConfigID string, vci *config.VCIScenario) (*openid4vci.CredentialResponse, error) {
	body := map[string]any{}
	if credentialConfigID != "" {
		body["credential_configuration_id"] = credentialConfigID
	}

	if vci.ProofType != "none" {
		proofJWT, err := c.createProofJWT(ctx, credentialEndpoint, cNonce)
		if err != nil {
			return nil, fmt.Errorf("creating proof JWT: %w", err)
		}
		body["proofs"] = map[string]any{
			"jwt": []string{proofJWT},
		}
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, credentialEndpoint, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	if tokenType == "DPoP" || vci.UseDPoP {
		dpopToken, err := c.createDPoPProof(http.MethodPost, credentialEndpoint, accessToken)
		if err != nil {
			return nil, fmt.Errorf("creating DPoP proof for credential: %w", err)
		}
		req.Header.Set("DPoP", dpopToken)
		req.Header.Set("Authorization", "DPoP "+accessToken)
	} else {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("credential request HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var credResp openid4vci.CredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&credResp); err != nil {
		return nil, err
	}
	return &credResp, nil
}

func (c *Client) pollDeferredCredential(ctx context.Context, deferredEndpoint, accessToken, tokenType, transactionID string, vci *config.VCIScenario) (*openid4vci.CredentialResponse, error) {
	interval := vci.DeferredPollInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	maxAttempts := vci.DeferredPollMaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 10
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c.log.Info("polling deferred credential", "attempt", attempt, "transaction_id", transactionID)

		body, _ := json.Marshal(openid4vci.DeferredCredentialRequest{
			TransactionID: transactionID,
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, deferredEndpoint, strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if tokenType == "DPoP" {
			req.Header.Set("Authorization", "DPoP "+accessToken)
		} else {
			req.Header.Set("Authorization", "Bearer "+accessToken)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			var credResp openid4vci.CredentialResponse
			if err := json.NewDecoder(resp.Body).Decode(&credResp); err != nil {
				if closeErr := resp.Body.Close(); closeErr != nil {
					return nil, fmt.Errorf("%w; close body: %w", err, closeErr)
				}
				return nil, err
			}
			if err := resp.Body.Close(); err != nil {
				return nil, fmt.Errorf("close body: %w", err)
			}

			if len(credResp.Credentials) > 0 {
				return &credResp, nil
			}
			if credResp.TransactionID != "" {
				transactionID = credResp.TransactionID
			}
		} else {
			if err := resp.Body.Close(); err != nil {
				return nil, fmt.Errorf("close body: %w", err)
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}

	return nil, fmt.Errorf("deferred credential not ready after %d attempts", maxAttempts)
}

func (c *Client) sendNotification(ctx context.Context, notificationEndpoint, accessToken, tokenType, notificationID, event string) error {
	body, _ := json.Marshal(openid4vci.NotificationRequest{
		NotificationID: notificationID,
		Event:          event,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notificationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tokenType == "DPoP" {
		req.Header.Set("Authorization", "DPoP "+accessToken)
	} else {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notification HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ---------- Crypto helpers ----------

func (c *Client) createProofJWT(ctx context.Context, audience, cNonce string) (string, error) {
	_, alg := jose.GetSigningMethodFromKey(c.signingKey)

	header := jwtv5.MapClaims{
		"typ": "openid4vci-proof+jwt",
		"alg": alg,
	}

	jwkData, err := c.publicKeyJWK()
	if err != nil {
		return "", err
	}
	header["jwk"] = jwkData

	body := jwtv5.MapClaims{
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	if cNonce != "" {
		body["nonce"] = cNonce
	}
	if c.cfg.Wallet.ClientID != "" {
		body["iss"] = c.cfg.Wallet.ClientID
	}

	signingMethod, _ := jose.GetSigningMethodFromKey(c.signingKey)
	token := jwtv5.NewWithClaims(signingMethod, body)
	maps.Copy(token.Header, header)

	signed, err := token.SignedString(c.signingKey)
	if err != nil {
		return "", fmt.Errorf("signing proof JWT: %w", err)
	}
	return signed, nil
}

func (c *Client) createDPoPProof(method, uri, accessToken string) (string, error) {
	_, alg := jose.GetSigningMethodFromKey(c.signingKey)

	jwkData, err := c.publicKeyJWK()
	if err != nil {
		return "", err
	}

	header := jwtv5.MapClaims{
		"typ": "dpop+jwt",
		"alg": alg,
		"jwk": jwkData,
	}

	body := jwtv5.MapClaims{
		"jti": uuid.New().String(),
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
	}

	if accessToken != "" {
		h := sha256.Sum256([]byte(accessToken))
		body["ath"] = base64.RawURLEncoding.EncodeToString(h[:])
	}

	signingMethod, _ := jose.GetSigningMethodFromKey(c.signingKey)
	token := jwtv5.NewWithClaims(signingMethod, body)
	maps.Copy(token.Header, header)

	signed, err := token.SignedString(c.signingKey)
	if err != nil {
		return "", fmt.Errorf("signing DPoP proof: %w", err)
	}
	return signed, nil
}

func (c *Client) publicKeyJWK() (map[string]any, error) {
	var pubKey crypto.PublicKey
	switch k := c.signingKey.(type) {
	case *ecdsa.PrivateKey:
		pubKey = k.Public()
	default:
		return nil, fmt.Errorf("unsupported key type for JWK: %T", c.signingKey)
	}

	ecKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA public key")
	}

	return map[string]any{
		"kty": "EC",
		"crv": ecKey.Curve.Params().Name,
		"x":   base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()),
	}, nil
}

func (c *Client) detectFormat(rawCredential string) string {
	if strings.Contains(rawCredential, "~") {
		return "vc+sd-jwt"
	}
	parts := strings.Split(rawCredential, ".")
	if len(parts) == 3 {
		return "jwt_vc_json"
	}
	return "unknown"
}

func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
