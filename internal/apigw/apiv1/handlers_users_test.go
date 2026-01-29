package apiv1

import (
	"context"
	"testing"
	"vc/internal/apigw/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/sdjwtvc"
	"vc/pkg/vcclient"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuthContextStore mocks the authorization context store
type mockAuthContextStore struct {
	authContexts map[string]*model.AuthorizationContext
	err          error
}

func newMockAuthContextStore() *mockAuthContextStore {
	return &mockAuthContextStore{
		authContexts: make(map[string]*model.AuthorizationContext),
	}
}

func (m *mockAuthContextStore) Save(ctx context.Context, doc *model.AuthorizationContext) error {
	if m.err != nil {
		return m.err
	}
	// Index by request_uri and verifier_response_code for lookups
	if doc.RequestURI != "" {
		m.authContexts["request_uri:"+doc.RequestURI] = doc
	}
	if doc.VerifierResponseCode != "" {
		m.authContexts["response_code:"+doc.VerifierResponseCode] = doc
	}
	return nil
}

func (m *mockAuthContextStore) Get(ctx context.Context, query *model.AuthorizationContext) (*model.AuthorizationContext, error) {
	if m.err != nil {
		return nil, m.err
	}
	if query.RequestURI != "" {
		if doc, ok := m.authContexts["request_uri:"+query.RequestURI]; ok {
			return doc, nil
		}
	}
	if query.VerifierResponseCode != "" {
		if doc, ok := m.authContexts["response_code:"+query.VerifierResponseCode]; ok {
			return doc, nil
		}
	}
	return nil, db.ErrNoDocuments
}

func (m *mockAuthContextStore) GetWithAccessToken(ctx context.Context, token string) (*model.AuthorizationContext, error) {
	return nil, nil
}

func (m *mockAuthContextStore) ForfeitAuthorizationCode(ctx context.Context, query *model.AuthorizationContext) (*model.AuthorizationContext, error) {
	return nil, nil
}

func (m *mockAuthContextStore) Consent(ctx context.Context, query *model.AuthorizationContext) error {
	return nil
}

func (m *mockAuthContextStore) AddToken(ctx context.Context, code string, token *model.Token) error {
	return nil
}

func (m *mockAuthContextStore) SetAuthenticSource(ctx context.Context, query *model.AuthorizationContext, authenticSource string) error {
	return nil
}

func (m *mockAuthContextStore) AddIdentity(ctx context.Context, query *model.AuthorizationContext, input *model.AuthorizationContext) error {
	return nil
}

// mockUsersStore mocks the users store
type mockUsersStore struct {
	users map[string]*model.OAuthUsers
	err   error
}

func newMockUsersStore() *mockUsersStore {
	return &mockUsersStore{
		users: make(map[string]*model.OAuthUsers),
	}
}

func (m *mockUsersStore) Save(ctx context.Context, doc *model.OAuthUsers) error {
	if m.err != nil {
		return m.err
	}
	m.users[doc.Username] = doc
	return nil
}

func (m *mockUsersStore) GetUser(ctx context.Context, username string) (*model.OAuthUsers, error) {
	if m.err != nil {
		return nil, m.err
	}
	if user, ok := m.users[username]; ok {
		return user, nil
	}
	return nil, db.ErrNoDocuments
}

func (m *mockUsersStore) GetHashedPassword(ctx context.Context, username string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if user, ok := m.users[username]; ok {
		return user.Password, nil
	}
	return "", nil
}

// TestUserLookup_BasicAuth tests the UserLookup function with basic username/password authentication.
// This simulates the traditional authentication flow (not PID auth).
func TestUserLookup_BasicAuth(t *testing.T) {
	ctx := t.Context()
	log, _ := logger.New("test", "", false)

	// Create mock stores
	authContextStore := newMockAuthContextStore()
	usersStore := newMockUsersStore()

	// Insert test user
	testUser := &model.OAuthUsers{
		Username: "testuser",
		Password: "$2a$10$abcdefghijklmnopqrstuv", // bcrypt hash placeholder
		Identity: &model.Identity{
			GivenName:               "John",
			FamilyName:              "Doe",
			BirthDate:               "1990-01-01",
			ExpiryDate:              "2030-01-01",
			Schema:                  &model.IdentitySchema{Name: "SE", Version: "1.0.0"},
			AuthenticSourcePersonID: "test-person-123",
		},
	}
	err := usersStore.Save(ctx, testUser)
	require.NoError(t, err)

	// Insert authorization context
	testAuthContext := &model.AuthorizationContext{
		SessionID:           "session-123",
		RequestURI:          "https://issuer.example.com/request/123",
		Code:                "auth-code-123",
		State:               "state-456",
		WalletURI:           "https://wallet.example.com/callback",
		ClientID:            "test-client",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           1735000000,
		VCT:                 "urn:eudi:pid:1",
	}
	err = authContextStore.Save(ctx, testAuthContext)
	require.NoError(t, err)

	client := &Client{
		log:              log,
		authContextStore: authContextStore,
		usersStore:       usersStore,
	}

	req := &vcclient.UserLookupRequest{
		RequestURI: "https://issuer.example.com/request/123",
		Username:   "testuser",
		AuthMethod: model.AuthMethodBasic,
	}

	result, err := client.UserLookup(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.RedirectURL, "https://wallet.example.com/callback")
	assert.Contains(t, result.RedirectURL, "code=auth-code-123")
	assert.Contains(t, result.RedirectURL, "state=state-456")

	assert.Equal(t, "John", result.SVGTemplateClaims["given_name"].Value)
	assert.Equal(t, "Given name", result.SVGTemplateClaims["given_name"].Label)
	assert.Equal(t, "Doe", result.SVGTemplateClaims["family_name"].Value)
	assert.Equal(t, "Family name", result.SVGTemplateClaims["family_name"].Label)
	assert.Equal(t, "1990-01-01", result.SVGTemplateClaims["birth_date"].Value)
	assert.Equal(t, "2030-01-01", result.SVGTemplateClaims["expiry_date"].Value)
}

// TestUserLookup_PIDAuth tests the UserLookup function with PID authentication (OpenID4VP).
// This simulates authentication using verifiable credentials presented by the wallet.
func TestUserLookup_PIDAuth(t *testing.T) {
	ctx := t.Context()
	log, _ := logger.New("test", "", false)

	// Create mock stores
	authContextStore := newMockAuthContextStore()

	// Insert authorization context for PID auth
	testAuthContext := &model.AuthorizationContext{
		SessionID:            "session-456",
		VerifierResponseCode: "response-code-xyz",
		Code:                 "auth-code-789",
		State:                "state-abc",
		WalletURI:            "https://wallet.example.com/callback",
		ClientID:             "test-client",
		CodeChallenge:        "challenge",
		CodeChallengeMethod:  "S256",
		ExpiresAt:            1735000000,
		RequestURI:           "https://issuer.example.com/request/456",
		VCT:                  "urn:eudi:pid:1",
		AuthenticSource:      "test-source",
	}
	err := authContextStore.Save(ctx, testAuthContext)
	require.NoError(t, err)

	// Create document cache with test data
	cache := ttlcache.New[string, map[string]*model.CompleteDocument]()
	doc := model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: "test-source",
			VCT:             "urn:eudi:pid:1",
			DocumentVersion: "1.0.0",
			DocumentID:      "doc-123",
		},
		DocumentData: map[string]any{
			"given_name":  "Jane",
			"family_name": "Smith",
			"birth_date":  "1985-05-15",
		},
		Identities: []model.Identity{
			{
				GivenName:               "Jane",
				FamilyName:              "Smith",
				BirthDate:               "1985-05-15",
				Schema:                  &model.IdentitySchema{Name: "SE", Version: "1.0.0"},
				AuthenticSourcePersonID: "test-person-456",
			},
		},
		DocumentDisplay: &model.DocumentDisplay{
			Version: "1.0.0",
			Type:    "secure",
			DescriptionStructured: map[string]any{
				"en": "Personal ID",
			},
		},
		DocumentDataVersion: "1.0.0",
	}
	docs := map[string]*model.CompleteDocument{
		"test-source": &doc,
	}
	cache.Set("session-456", docs, ttlcache.DefaultTTL)

	client := &Client{
		log:              log,
		documentCache:    cache,
		authContextStore: authContextStore,
	}

	// Create VCTM with claims
	givenNamePath := "given_name"
	familyNamePath := "family_name"
	birthDatePath := "birth_date"

	req := &vcclient.UserLookupRequest{
		RequestURI:   "https://issuer.example.com/request/456",
		ResponseCode: "response-code-xyz",
		AuthMethod:   model.AuthMethodPID,
		VCTM: &sdjwtvc.VCTM{
			Claims: []sdjwtvc.Claim{
				{
					Path:  []*string{&givenNamePath},
					SVGID: "given_name",
					Display: []sdjwtvc.ClaimDisplay{
						{Label: "Given Name"},
					},
				},
				{
					Path:  []*string{&familyNamePath},
					SVGID: "family_name",
					Display: []sdjwtvc.ClaimDisplay{
						{Label: "Family Name"},
					},
				},
				{
					Path:  []*string{&birthDatePath},
					SVGID: "birth_date",
					Display: []sdjwtvc.ClaimDisplay{
						{Label: "Birth Date"},
					},
				},
			},
		},
	}

	result, err := client.UserLookup(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.RedirectURL, "https://wallet.example.com/callback")
	assert.Contains(t, result.RedirectURL, "code=auth-code-789")
	assert.Contains(t, result.RedirectURL, "state=state-abc")

	assert.Equal(t, "Jane", result.SVGTemplateClaims["given_name"].Value)
	assert.Equal(t, "Given Name", result.SVGTemplateClaims["given_name"].Label)
	assert.Equal(t, "Smith", result.SVGTemplateClaims["family_name"].Value)
	assert.Equal(t, "Family Name", result.SVGTemplateClaims["family_name"].Label)
	assert.Equal(t, "1985-05-15", result.SVGTemplateClaims["birth_date"].Value)
	assert.Equal(t, "Birth Date", result.SVGTemplateClaims["birth_date"].Label)
}

// TestUserLookup_PIDAuth_NoDocuments tests error handling when no documents are found in cache for PID auth.
func TestUserLookup_PIDAuth_NoDocuments(t *testing.T) {
	ctx := t.Context()
	log, _ := logger.New("test", "", false)

	// Create mock stores
	authContextStore := newMockAuthContextStore()

	// Insert authorization context
	testAuthContext := &model.AuthorizationContext{
		SessionID:            "session-no-docs",
		VerifierResponseCode: "response-code-123",
		Code:                 "auth-code",
		State:                "state",
		WalletURI:            "https://wallet.example.com/callback",
		ClientID:             "test-client",
		CodeChallenge:        "challenge",
		CodeChallengeMethod:  "S256",
		ExpiresAt:            1735000000,
		RequestURI:           "https://issuer.example.com/request/789",
		VCT:                  "urn:eudi:pid:1",
	}
	err := authContextStore.Save(ctx, testAuthContext)
	require.NoError(t, err)

	// Create empty document cache
	cache := ttlcache.New[string, map[string]*model.CompleteDocument]()

	client := &Client{
		log:              log,
		documentCache:    cache,
		authContextStore: authContextStore,
	}

	req := &vcclient.UserLookupRequest{
		RequestURI:   "https://issuer.example.com/request/789",
		ResponseCode: "response-code-123",
		AuthMethod:   model.AuthMethodPID,
		VCTM:         &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{}},
	}

	result, err := client.UserLookup(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no documents found for session")
}

func TestUserLookup_UnsupportedAuthMethod(t *testing.T) {
	ctx := t.Context()
	log, _ := logger.New("test", "", false)

	// Create mock stores
	authContextStore := newMockAuthContextStore()

	// Insert authorization context
	testAuthContext := &model.AuthorizationContext{
		SessionID:           "session-999",
		RequestURI:          "https://issuer.example.com/request/999",
		Code:                "auth-code",
		State:               "state",
		WalletURI:           "https://wallet.example.com/callback",
		ClientID:            "test-client",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           1735000000,
		VCT:                 "urn:eudi:pid:1",
	}
	err := authContextStore.Save(ctx, testAuthContext)
	require.NoError(t, err)

	client := &Client{
		log:              log,
		authContextStore: authContextStore,
	}

	req := &vcclient.UserLookupRequest{
		RequestURI: "https://issuer.example.com/request/999",
		AuthMethod: "unsupported_method",
	}

	result, err := client.UserLookup(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "unsupported auth method")
}

func TestUserLookup_ClaimExtraction(t *testing.T) {
	// Test the claim extraction logic in isolation
	documentData := map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
		"birth_date":  "1990-01-01",
	}

	givenNamePath := "given_name"
	familyNamePath := "family_name"
	birthDatePath := "birth_date"

	vctm := &sdjwtvc.VCTM{
		Claims: []sdjwtvc.Claim{
			{
				Path:  []*string{&givenNamePath},
				SVGID: "given_name",
				Display: []sdjwtvc.ClaimDisplay{
					{Label: "Given Name"},
				},
			},
			{
				Path:  []*string{&familyNamePath},
				SVGID: "family_name",
				Display: []sdjwtvc.ClaimDisplay{
					{Label: "Family Name"},
				},
			},
			{
				Path:  []*string{&birthDatePath},
				SVGID: "birth_date",
				Display: []sdjwtvc.ClaimDisplay{
					{Label: "Birth Date"},
				},
			},
		},
	}

	jsonPaths, err := vctm.ClaimJSONPath()
	require.NoError(t, err)

	claimValues, err := sdjwtvc.ExtractClaimsByJSONPath(documentData, jsonPaths.Displayable)
	require.NoError(t, err)

	assert.Equal(t, "John", claimValues["given_name"])
	assert.Equal(t, "Doe", claimValues["family_name"])
	assert.Equal(t, "1990-01-01", claimValues["birth_date"])

	// Build SVG template claims as done in UserLookup
	svgTemplateClaims := map[string]vcclient.SVGClaim{}
	for _, claim := range vctm.Claims {
		value, ok := claimValues[claim.SVGID].(string)
		if !ok {
			continue
		}

		if claim.SVGID != "" {
			svgTemplateClaims[claim.SVGID] = vcclient.SVGClaim{
				Label: claim.Display[0].Label,
				Value: value,
			}
		}
	}

	assert.Equal(t, "John", svgTemplateClaims["given_name"].Value)
	assert.Equal(t, "Given Name", svgTemplateClaims["given_name"].Label)
	assert.Equal(t, "Doe", svgTemplateClaims["family_name"].Value)
	assert.Equal(t, "Family Name", svgTemplateClaims["family_name"].Label)
	assert.Equal(t, "1990-01-01", svgTemplateClaims["birth_date"].Value)
	assert.Equal(t, "Birth Date", svgTemplateClaims["birth_date"].Label)
}
