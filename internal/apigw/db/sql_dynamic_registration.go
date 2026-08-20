package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/SUNET/vc/pkg/sqlstore"

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/codes"
)

// SQLDynamicRegistrationColl is a SQL-backed implementation of DynamicRegistrationStore.
type SQLDynamicRegistrationColl struct {
	Service *Service
	db      *sqlx.DB
	dialect sqlstore.Dialect
}

// NewSQLDynamicRegistrationColl creates a SQL-backed DynamicRegistrationStore.
func NewSQLDynamicRegistrationColl(service *Service, db *sqlx.DB, dialect sqlstore.Dialect) *SQLDynamicRegistrationColl {
	return &SQLDynamicRegistrationColl{Service: service, db: db, dialect: dialect}
}

type dynamicRegistrationRow struct {
	ClientID                string    `db:"client_id"`
	ClientSecret            string    `db:"client_secret"`
	RegistrationAccessToken string    `db:"registration_access_token"`
	RegistrationClientURI   string    `db:"registration_client_uri"`
	ClientSecretExpiresAt   int64     `db:"client_secret_expires_at"`
	RegisteredAt            time.Time `db:"registered_at"`
}

// Save stores or replaces dynamic registration credentials, upserting by client_id.
func (c *SQLDynamicRegistrationColl) Save(ctx context.Context, creds *DynamicRegistrationCredentials) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:dynamic_registration:save")
	defer span.End()

	creds.RegisteredAt = time.Now().UTC()

	updateCols := []string{
		"client_secret", "registration_access_token", "registration_client_uri",
		"client_secret_expires_at", "registered_at",
	}
	query := c.dialect.Rebind(`INSERT INTO oidc_dynamic_registration
		(client_id, client_secret, registration_access_token, registration_client_uri, client_secret_expires_at, registered_at)
		VALUES (?, ?, ?, ?, ?, ?) ` + c.dialect.UpsertClause([]string{"client_id"}, updateCols))

	_, err := c.db.ExecContext(ctx, query,
		creds.ClientID, creds.ClientSecret, creds.RegistrationAccessToken,
		creds.RegistrationClientURI, creds.ClientSecretExpiresAt, creds.RegisteredAt,
	)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Get returns the stored credentials, or nil if none exist or the client secret has expired.
func (c *SQLDynamicRegistrationColl) Get(ctx context.Context) (*DynamicRegistrationCredentials, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:dynamic_registration:get")
	defer span.End()

	query := c.dialect.Rebind(`SELECT client_id, client_secret, registration_access_token,
		registration_client_uri, client_secret_expires_at, registered_at
		FROM oidc_dynamic_registration LIMIT 1`)

	var row dynamicRegistrationRow
	if err := c.db.GetContext(ctx, &row, query); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	creds := &DynamicRegistrationCredentials{
		ClientID:                row.ClientID,
		ClientSecret:            row.ClientSecret,
		RegistrationAccessToken: row.RegistrationAccessToken,
		RegistrationClientURI:   row.RegistrationClientURI,
		ClientSecretExpiresAt:   row.ClientSecretExpiresAt,
		RegisteredAt:            row.RegisteredAt,
	}

	if creds.ClientSecretExpiresAt > 0 {
		expiresAt := time.Unix(creds.ClientSecretExpiresAt, 0)
		if time.Now().After(expiresAt) {
			c.Service.log.Info("Dynamic registration credentials expired", "client_id", creds.ClientID, "expired_at", expiresAt)
			return nil, nil
		}
	}

	return creds, nil
}
