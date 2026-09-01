package db

import (
	"context"

	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sqlstore"

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/codes"
)

// SQLCredentialOfferColl is a SQL-backed implementation of CredentialOfferStore.
type SQLCredentialOfferColl struct {
	Service *Service
	db      *sqlx.DB
	dialect sqlstore.Dialect
}

// NewSQLCredentialOfferColl creates a SQL-backed CredentialOfferStore.
func NewSQLCredentialOfferColl(service *Service, db *sqlx.DB, dialect sqlstore.Dialect) *SQLCredentialOfferColl {
	return &SQLCredentialOfferColl{Service: service, db: db, dialect: dialect}
}

type credentialOfferRow struct {
	UUID       string                                              `db:"uuid"`
	Parameters sqlstore.JSON[openid4vci.CredentialOfferParameters] `db:"credential_offer_parameters"`
}

// Save saves one credential offer document.
func (c *SQLCredentialOfferColl) Save(ctx context.Context, doc *CredentialOfferDocument) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:credential_offer:save")
	defer span.End()

	query := c.dialect.Rebind(`INSERT INTO credential_offer (uuid, credential_offer_parameters) VALUES (?, ?)`)
	_, err := c.db.ExecContext(ctx, query,
		doc.UUID,
		sqlstore.JSON[openid4vci.CredentialOfferParameters]{V: doc.CredentialOfferParameters},
	)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Delete deletes one credential offer by uuid.
func (c *SQLCredentialOfferColl) Delete(ctx context.Context, uuid string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:credential_offer:delete")
	defer span.End()

	query := c.dialect.Rebind(`DELETE FROM credential_offer WHERE uuid = ?`)
	if _, err := c.db.ExecContext(ctx, query, uuid); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Get returns the credential offer document for the given uuid.
func (c *SQLCredentialOfferColl) Get(ctx context.Context, uuid string) (*CredentialOfferDocument, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:sql:credential_offer:get")
	defer span.End()

	query := c.dialect.Rebind(`SELECT uuid, credential_offer_parameters FROM credential_offer WHERE uuid = ?`)
	var row credentialOfferRow
	if err := c.db.GetContext(ctx, &row, query, uuid); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &CredentialOfferDocument{
		UUID:                      row.UUID,
		CredentialOfferParameters: row.Parameters.V,
	}, nil
}
