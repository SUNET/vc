package db

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Client represents an OIDC client (Relying Party)
// Implements RFC 7591 (OAuth 2.0 Dynamic Client Registration Protocol)
// and RFC 7592 (OAuth 2.0 Dynamic Client Registration Management Protocol)
type Client struct {
	// Core OAuth 2.0 / OIDC fields
	ClientID                string   `bson:"client_id" json:"client_id"`
	ClientSecretHash        string   `bson:"client_secret_hash,omitempty" json:"-"`
	RedirectURIs            []string `bson:"redirect_uris" json:"redirect_uris"`
	GrantTypes              []string `bson:"grant_types" json:"grant_types"`
	ResponseTypes           []string `bson:"response_types" json:"response_types"`
	TokenEndpointAuthMethod string   `bson:"token_endpoint_auth_method" json:"token_endpoint_auth_method"`
	AllowedScopes           []string `bson:"allowed_scopes" json:"allowed_scopes"`
	DefaultScopes           []string `bson:"default_scopes,omitempty" json:"default_scopes,omitempty"`
	SubjectType             string   `bson:"subject_type" json:"subject_type"` // "public" or "pairwise"
	JWKSUri                 string   `bson:"jwks_uri,omitempty" json:"jwks_uri,omitempty"`
	JWKS                    any      `bson:"jwks,omitempty" json:"jwks,omitempty"`
	RequirePKCE             bool     `bson:"require_pkce" json:"require_pkce"`
	RequireCodeChallenge    bool     `bson:"require_code_challenge" json:"require_code_challenge"`

	// RFC 7591 Client Metadata (optional fields)
	ClientName               string   `bson:"client_name,omitempty" json:"client_name,omitempty"`
	ClientURI                string   `bson:"client_uri,omitempty" json:"client_uri,omitempty"`
	LogoURI                  string   `bson:"logo_uri,omitempty" json:"logo_uri,omitempty"`
	Contacts                 []string `bson:"contacts,omitempty" json:"contacts,omitempty"`
	TosURI                   string   `bson:"tos_uri,omitempty" json:"tos_uri,omitempty"`
	PolicyURI                string   `bson:"policy_uri,omitempty" json:"policy_uri,omitempty"`
	SoftwareID               string   `bson:"software_id,omitempty" json:"software_id,omitempty"`
	SoftwareVersion          string   `bson:"software_version,omitempty" json:"software_version,omitempty"`
	ApplicationType          string   `bson:"application_type,omitempty" json:"application_type,omitempty"` // "web" or "native"
	SectorIdentifierURI      string   `bson:"sector_identifier_uri,omitempty" json:"sector_identifier_uri,omitempty"`
	IDTokenSignedResponseAlg string   `bson:"id_token_signed_response_alg,omitempty" json:"id_token_signed_response_alg,omitempty"`
	DefaultMaxAge            int      `bson:"default_max_age,omitempty" json:"default_max_age,omitempty"`
	RequireAuthTime          bool     `bson:"require_auth_time,omitempty" json:"require_auth_time,omitempty"`
	DefaultACRValues         []string `bson:"default_acr_values,omitempty" json:"default_acr_values,omitempty"`
	InitiateLoginURI         string   `bson:"initiate_login_uri,omitempty" json:"initiate_login_uri,omitempty"`
	RequestURIs              []string `bson:"request_uris,omitempty" json:"request_uris,omitempty"`

	// RFC 7636 PKCE metadata
	CodeChallengeMethod string `bson:"code_challenge_method,omitempty" json:"code_challenge_method,omitempty"`

	// RFC 7592 Client Management
	RegistrationAccessTokenHash string `bson:"registration_access_token_hash,omitempty" json:"-"`
	ClientIDIssuedAt            int64  `bson:"client_id_issued_at,omitempty" json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt       int64  `bson:"client_secret_expires_at,omitempty" json:"client_secret_expires_at,omitempty"`
}

// ClientCollection provides database operations for clients
type ClientCollection struct {
	Service    *Service
	collection *mongo.Collection
}

// createIndex creates required indexes for the clients collection.
// A unique index on client_id is critical for correct behaviour in HA /
// replica-set deployments: without it, FindOne by client_id performs a full
// collection scan that may miss recently-written documents on secondaries,
// and uniqueness of client_id is not enforced.
func (c *ClientCollection) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:clients:createIndex")
	defer span.End()

	indexClientIDUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "client_id", Value: 1},
		},
		Options: options.Index().SetName("client_id_uniq").SetUnique(true),
	}
	_, err := c.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{indexClientIDUniq})
	return err
}

// GetByClientID retrieves a client by client ID
func (c *ClientCollection) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:clients:get_by_client_id")
	defer span.End()

	var client Client
	err := c.collection.FindOne(ctx, bson.M{"client_id": clientID}).Decode(&client)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		c.Service.log.Error(err, "Failed to get client")
		return nil, err
	}

	return &client, nil
}

// Create creates a new client
func (c *ClientCollection) Create(ctx context.Context, client *Client) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:clients:create")
	defer span.End()

	_, err := c.collection.InsertOne(ctx, client)
	if err != nil {
		c.Service.log.Error(err, "Failed to create client")
		return err
	}

	return nil
}

// Update updates a client
func (c *ClientCollection) Update(ctx context.Context, client *Client) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:clients:update")
	defer span.End()

	_, err := c.collection.ReplaceOne(ctx, bson.M{"client_id": client.ClientID}, client)
	if err != nil {
		c.Service.log.Error(err, "Failed to update client")
		return err
	}

	return nil
}

// Delete deletes a client
func (c *ClientCollection) Delete(ctx context.Context, clientID string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:clients:delete")
	defer span.End()

	_, err := c.collection.DeleteOne(ctx, bson.M{"client_id": clientID})
	if err != nil {
		c.Service.log.Error(err, "Failed to delete client")
		return err
	}

	return nil
}
