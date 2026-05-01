package apiv2

import (
	"context"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/model"

	"go.opentelemetry.io/otel/codes"
)

// GetDocumentForCredential resolves an identity to a v2 document for credential issuance.
// It first resolves identity attributes to an identifier, then fetches the matching document.
// This is the v2 equivalent of the v1 GetDocumentWithIdentity flow.
func (c *Client) GetDocumentForCredential(ctx context.Context, authenticSource, scope string, identityAttributes map[string]string) (*model.V2Document, error) {
	ctx, span := c.tracer.Start(ctx, "apiv2:getDocumentForCredential")
	defer span.End()

	// Resolve identity attributes to identifier
	identifier, err := c.datastoreStore.GetIdentityMapping(ctx, authenticSource, identityAttributes)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// List documents for this identifier and scope
	docs, err := c.datastoreStore.ListDocuments(ctx, authenticSource, identifier, scope)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if len(docs) == 0 {
		return nil, db.ErrNoDocuments
	}

	// Return the first matching document
	return docs[0], nil
}

// GetDocumentByIdentifier fetches a v2 document directly by identifier and scope.
// Used when the identifier is already known (e.g. from a session cache).
func (c *Client) GetDocumentByIdentifier(ctx context.Context, authenticSource, scope, identifier string) (*model.V2Document, error) {
	ctx, span := c.tracer.Start(ctx, "apiv2:getDocumentByIdentifier")
	defer span.End()

	docs, err := c.datastoreStore.ListDocuments(ctx, authenticSource, identifier, scope)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if len(docs) == 0 {
		return nil, db.ErrNoDocuments
	}

	return docs[0], nil
}

// IdentityToAttributes converts a v1 Identity object to v2 mapping attributes.
// This enables backward-compatible identity resolution using the v2 mapping system.
func IdentityToAttributes(identity *model.Identity) map[string]string {
	if identity == nil {
		return nil
	}

	attrs := make(map[string]string)

	if identity.FamilyName != "" {
		attrs["family_name"] = identity.FamilyName
	}
	if identity.GivenName != "" {
		attrs["given_name"] = identity.GivenName
	}
	if identity.BirthDate != "" {
		attrs["birth_date"] = identity.BirthDate
	}
	if identity.PersonalAdministrativeNumber != "" {
		attrs["personal_administrative_number"] = identity.PersonalAdministrativeNumber
	}

	return attrs
}

// HasDocument checks if there's a v2 document available for the given identity attributes.
// Returns true if the identity can be resolved AND at least one document exists.
func (c *Client) HasDocument(ctx context.Context, authenticSource, scope string, identityAttributes map[string]string) bool {
	if len(identityAttributes) == 0 {
		return false
	}

	identifier, err := c.datastoreStore.GetIdentityMapping(ctx, authenticSource, identityAttributes)
	if err != nil {
		return false
	}

	docs, err := c.datastoreStore.ListDocuments(ctx, authenticSource, identifier, scope)
	if err != nil {
		return false
	}

	return len(docs) > 0
}
