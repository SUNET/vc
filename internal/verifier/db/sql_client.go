package db

import (
	"context"
	"database/sql"
	"errors"

	"github.com/SUNET/vc/pkg/sqlstore"

	"github.com/jmoiron/sqlx"
)

// SQLClientColl is a SQL-backed implementation of ClientStore.
type SQLClientColl struct {
	Service *Service
	db      *sqlx.DB
	dialect sqlstore.Dialect
}

// NewSQLClientColl creates a SQL-backed ClientStore.
func NewSQLClientColl(service *Service, db *sqlx.DB, dialect sqlstore.Dialect) *SQLClientColl {
	return &SQLClientColl{Service: service, db: db, dialect: dialect}
}

// clientRow mirrors Client field-for-field. Scalar fields are stored as
// plain Go types (not sql.Null*): every write path always supplies a
// concrete (possibly zero) value, so the schema's nullable columns are
// permissive but never depended on to distinguish "unset" from "zero
// value" -- the Go zero value already means "unset" for these fields.
type clientRow struct {
	ClientID                    string                  `db:"client_id"`
	ClientSecretHash            string                  `db:"client_secret_hash"`
	RedirectURIs                sqlstore.JSON[[]string] `db:"redirect_uris"`
	GrantTypes                  sqlstore.JSON[[]string] `db:"grant_types"`
	ResponseTypes               sqlstore.JSON[[]string] `db:"response_types"`
	TokenEndpointAuthMethod     string                  `db:"token_endpoint_auth_method"`
	AllowedScopes               sqlstore.JSON[[]string] `db:"allowed_scopes"`
	DefaultScopes               sqlstore.JSON[[]string] `db:"default_scopes"`
	SubjectType                 string                  `db:"subject_type"`
	JWKSUri                     string                  `db:"jwks_uri"`
	JWKS                        sqlstore.JSON[any]      `db:"jwks"`
	RequirePKCE                 bool                    `db:"require_pkce"`
	RequireCodeChallenge        bool                    `db:"require_code_challenge"`
	ClientName                  string                  `db:"client_name"`
	ClientURI                   string                  `db:"client_uri"`
	LogoURI                     string                  `db:"logo_uri"`
	Contacts                    sqlstore.JSON[[]string] `db:"contacts"`
	TosURI                      string                  `db:"tos_uri"`
	PolicyURI                   string                  `db:"policy_uri"`
	SoftwareID                  string                  `db:"software_id"`
	SoftwareVersion             string                  `db:"software_version"`
	ApplicationType             string                  `db:"application_type"`
	SectorIdentifierURI         string                  `db:"sector_identifier_uri"`
	IDTokenSignedResponseAlg    string                  `db:"id_token_signed_response_alg"`
	DefaultMaxAge               int                     `db:"default_max_age"`
	RequireAuthTime             bool                    `db:"require_auth_time"`
	DefaultACRValues            sqlstore.JSON[[]string] `db:"default_acr_values"`
	InitiateLoginURI            string                  `db:"initiate_login_uri"`
	RequestURIs                 sqlstore.JSON[[]string] `db:"request_uris"`
	CodeChallengeMethod         string                  `db:"code_challenge_method"`
	RegistrationAccessTokenHash string                  `db:"registration_access_token_hash"`
	ClientIDIssuedAt            int64                   `db:"client_id_issued_at"`
	ClientSecretExpiresAt       int64                   `db:"client_secret_expires_at"`
}

func rowFromClient(c *Client) clientRow {
	return clientRow{
		ClientID:                    c.ClientID,
		ClientSecretHash:            c.ClientSecretHash,
		RedirectURIs:                sqlstore.JSON[[]string]{V: c.RedirectURIs},
		GrantTypes:                  sqlstore.JSON[[]string]{V: c.GrantTypes},
		ResponseTypes:               sqlstore.JSON[[]string]{V: c.ResponseTypes},
		TokenEndpointAuthMethod:     c.TokenEndpointAuthMethod,
		AllowedScopes:               sqlstore.JSON[[]string]{V: c.AllowedScopes},
		DefaultScopes:               sqlstore.JSON[[]string]{V: c.DefaultScopes},
		SubjectType:                 c.SubjectType,
		JWKSUri:                     c.JWKSUri,
		JWKS:                        sqlstore.JSON[any]{V: c.JWKS},
		RequirePKCE:                 c.RequirePKCE,
		RequireCodeChallenge:        c.RequireCodeChallenge,
		ClientName:                  c.ClientName,
		ClientURI:                   c.ClientURI,
		LogoURI:                     c.LogoURI,
		Contacts:                    sqlstore.JSON[[]string]{V: c.Contacts},
		TosURI:                      c.TosURI,
		PolicyURI:                   c.PolicyURI,
		SoftwareID:                  c.SoftwareID,
		SoftwareVersion:             c.SoftwareVersion,
		ApplicationType:             c.ApplicationType,
		SectorIdentifierURI:         c.SectorIdentifierURI,
		IDTokenSignedResponseAlg:    c.IDTokenSignedResponseAlg,
		DefaultMaxAge:               c.DefaultMaxAge,
		RequireAuthTime:             c.RequireAuthTime,
		DefaultACRValues:            sqlstore.JSON[[]string]{V: c.DefaultACRValues},
		InitiateLoginURI:            c.InitiateLoginURI,
		RequestURIs:                 sqlstore.JSON[[]string]{V: c.RequestURIs},
		CodeChallengeMethod:         c.CodeChallengeMethod,
		RegistrationAccessTokenHash: c.RegistrationAccessTokenHash,
		ClientIDIssuedAt:            c.ClientIDIssuedAt,
		ClientSecretExpiresAt:       c.ClientSecretExpiresAt,
	}
}

func (row clientRow) toClient() *Client {
	return &Client{
		ClientID:                    row.ClientID,
		ClientSecretHash:            row.ClientSecretHash,
		RedirectURIs:                row.RedirectURIs.V,
		GrantTypes:                  row.GrantTypes.V,
		ResponseTypes:               row.ResponseTypes.V,
		TokenEndpointAuthMethod:     row.TokenEndpointAuthMethod,
		AllowedScopes:               row.AllowedScopes.V,
		DefaultScopes:               row.DefaultScopes.V,
		SubjectType:                 row.SubjectType,
		JWKSUri:                     row.JWKSUri,
		JWKS:                        row.JWKS.V,
		RequirePKCE:                 row.RequirePKCE,
		RequireCodeChallenge:        row.RequireCodeChallenge,
		ClientName:                  row.ClientName,
		ClientURI:                   row.ClientURI,
		LogoURI:                     row.LogoURI,
		Contacts:                    row.Contacts.V,
		TosURI:                      row.TosURI,
		PolicyURI:                   row.PolicyURI,
		SoftwareID:                  row.SoftwareID,
		SoftwareVersion:             row.SoftwareVersion,
		ApplicationType:             row.ApplicationType,
		SectorIdentifierURI:         row.SectorIdentifierURI,
		IDTokenSignedResponseAlg:    row.IDTokenSignedResponseAlg,
		DefaultMaxAge:               row.DefaultMaxAge,
		RequireAuthTime:             row.RequireAuthTime,
		DefaultACRValues:            row.DefaultACRValues.V,
		InitiateLoginURI:            row.InitiateLoginURI,
		RequestURIs:                 row.RequestURIs.V,
		CodeChallengeMethod:         row.CodeChallengeMethod,
		RegistrationAccessTokenHash: row.RegistrationAccessTokenHash,
		ClientIDIssuedAt:            row.ClientIDIssuedAt,
		ClientSecretExpiresAt:       row.ClientSecretExpiresAt,
	}
}

// GetByClientID retrieves a client by client ID. Returns nil, nil if not
// found, matching the Mongo implementation.
func (c *SQLClientColl) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:sql:clients:get_by_client_id")
	defer span.End()

	query := c.dialect.Rebind(`SELECT client_id, client_secret_hash, redirect_uris, grant_types, response_types,
		token_endpoint_auth_method, allowed_scopes, default_scopes, subject_type, jwks_uri, jwks,
		require_pkce, require_code_challenge, client_name, client_uri, logo_uri, contacts, tos_uri, policy_uri,
		software_id, software_version, application_type, sector_identifier_uri, id_token_signed_response_alg,
		default_max_age, require_auth_time, default_acr_values, initiate_login_uri, request_uris,
		code_challenge_method, registration_access_token_hash, client_id_issued_at, client_secret_expires_at
		FROM clients WHERE client_id = ?`)

	var row clientRow
	if err := c.db.GetContext(ctx, &row, query, clientID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		c.Service.log.Error(err, "Failed to get client")
		return nil, err
	}

	return row.toClient(), nil
}

// Create creates a new client.
func (c *SQLClientColl) Create(ctx context.Context, client *Client) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:sql:clients:create")
	defer span.End()

	row := rowFromClient(client)
	query := c.dialect.Rebind(`INSERT INTO clients
		(client_id, client_secret_hash, redirect_uris, grant_types, response_types,
		 token_endpoint_auth_method, allowed_scopes, default_scopes, subject_type, jwks_uri, jwks,
		 require_pkce, require_code_challenge, client_name, client_uri, logo_uri, contacts, tos_uri, policy_uri,
		 software_id, software_version, application_type, sector_identifier_uri, id_token_signed_response_alg,
		 default_max_age, require_auth_time, default_acr_values, initiate_login_uri, request_uris,
		 code_challenge_method, registration_access_token_hash, client_id_issued_at, client_secret_expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)

	_, err := c.db.ExecContext(ctx, query,
		row.ClientID, row.ClientSecretHash, row.RedirectURIs, row.GrantTypes, row.ResponseTypes,
		row.TokenEndpointAuthMethod, row.AllowedScopes, row.DefaultScopes, row.SubjectType, row.JWKSUri, row.JWKS,
		row.RequirePKCE, row.RequireCodeChallenge, row.ClientName, row.ClientURI, row.LogoURI, row.Contacts, row.TosURI, row.PolicyURI,
		row.SoftwareID, row.SoftwareVersion, row.ApplicationType, row.SectorIdentifierURI, row.IDTokenSignedResponseAlg,
		row.DefaultMaxAge, row.RequireAuthTime, row.DefaultACRValues, row.InitiateLoginURI, row.RequestURIs,
		row.CodeChallengeMethod, row.RegistrationAccessTokenHash, row.ClientIDIssuedAt, row.ClientSecretExpiresAt,
	)
	if err != nil {
		c.Service.log.Error(err, "Failed to create client")
		return err
	}
	return nil
}

// Update updates a client, replacing every column. Silently does nothing if
// no client with that client_id exists, matching Mongo's ReplaceOne without upsert.
func (c *SQLClientColl) Update(ctx context.Context, client *Client) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:sql:clients:update")
	defer span.End()

	row := rowFromClient(client)
	query := c.dialect.Rebind(`UPDATE clients SET
		client_secret_hash = ?, redirect_uris = ?, grant_types = ?, response_types = ?,
		token_endpoint_auth_method = ?, allowed_scopes = ?, default_scopes = ?, subject_type = ?, jwks_uri = ?, jwks = ?,
		require_pkce = ?, require_code_challenge = ?, client_name = ?, client_uri = ?, logo_uri = ?, contacts = ?, tos_uri = ?, policy_uri = ?,
		software_id = ?, software_version = ?, application_type = ?, sector_identifier_uri = ?, id_token_signed_response_alg = ?,
		default_max_age = ?, require_auth_time = ?, default_acr_values = ?, initiate_login_uri = ?, request_uris = ?,
		code_challenge_method = ?, registration_access_token_hash = ?, client_id_issued_at = ?, client_secret_expires_at = ?
		WHERE client_id = ?`)

	_, err := c.db.ExecContext(ctx, query,
		row.ClientSecretHash, row.RedirectURIs, row.GrantTypes, row.ResponseTypes,
		row.TokenEndpointAuthMethod, row.AllowedScopes, row.DefaultScopes, row.SubjectType, row.JWKSUri, row.JWKS,
		row.RequirePKCE, row.RequireCodeChallenge, row.ClientName, row.ClientURI, row.LogoURI, row.Contacts, row.TosURI, row.PolicyURI,
		row.SoftwareID, row.SoftwareVersion, row.ApplicationType, row.SectorIdentifierURI, row.IDTokenSignedResponseAlg,
		row.DefaultMaxAge, row.RequireAuthTime, row.DefaultACRValues, row.InitiateLoginURI, row.RequestURIs,
		row.CodeChallengeMethod, row.RegistrationAccessTokenHash, row.ClientIDIssuedAt, row.ClientSecretExpiresAt,
		row.ClientID,
	)
	if err != nil {
		c.Service.log.Error(err, "Failed to update client")
		return err
	}
	return nil
}

// Delete deletes a client.
func (c *SQLClientColl) Delete(ctx context.Context, clientID string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:sql:clients:delete")
	defer span.End()

	query := c.dialect.Rebind(`DELETE FROM clients WHERE client_id = ?`)
	if _, err := c.db.ExecContext(ctx, query, clientID); err != nil {
		c.Service.log.Error(err, "Failed to delete client")
		return err
	}
	return nil
}
