package db

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// VCDatastoreV2Coll handles the v2 datastore and identity mapping collections.
type VCDatastoreV2Coll struct {
	Service     *Service
	DocColl     *mongo.Collection // vc.datastore_v2
	MappingColl *mongo.Collection // vc.identity_mappings
	log         *logger.Log
}

func (c *VCDatastoreV2Coll) createIndexes(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:createIndexes")
	defer span.End()

	// Document collection indexes
	docIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "meta.authentic_source", Value: 1},
				{Key: "meta.scope", Value: 1},
				{Key: "meta.document_id", Value: 1},
			},
			Options: options.Index().SetName("v2_document_unique").SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "meta.authentic_source", Value: 1},
				{Key: "identities", Value: 1},
				{Key: "meta.scope", Value: 1},
			},
			Options: options.Index().SetName("v2_identity_lookup"),
		},
	}
	if _, err := c.DocColl.Indexes().CreateMany(ctx, docIndexes); err != nil {
		return fmt.Errorf("failed to create document indexes: %w", err)
	}

	// Identity mapping collection indexes
	mappingIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "authentic_source", Value: 1},
				{Key: "identifier", Value: 1},
			},
			Options: options.Index().SetName("v2_mapping_unique").SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "authentic_source", Value: 1},
				{Key: "attributes", Value: 1},
			},
			Options: options.Index().SetName("v2_mapping_attributes_lookup"),
		},
	}
	if _, err := c.MappingColl.Indexes().CreateMany(ctx, mappingIndexes); err != nil {
		return fmt.Errorf("failed to create mapping indexes: %w", err)
	}

	return nil
}

// CreateIdentityMapping creates a new identity mapping. If Identifier is empty, a UUIDv7 is generated.
func (c *VCDatastoreV2Coll) CreateIdentityMapping(ctx context.Context, mapping *model.IdentityMapping) (string, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:createIdentityMapping")
	defer span.End()

	if mapping.Identifier == "" {
		id, err := uuid.NewV7()
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return "", fmt.Errorf("failed to generate UUIDv7: %w", err)
		}
		mapping.Identifier = id.String()
	}

	mapping.CreatedAt = time.Now().UTC()

	if _, err := c.MappingColl.InsertOne(ctx, mapping); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	return mapping.Identifier, nil
}

// GetIdentityMapping resolves attributes to an identifier within an authentic source.
func (c *VCDatastoreV2Coll) GetIdentityMapping(ctx context.Context, authenticSource string, attributes map[string]string) (string, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:getIdentityMapping")
	defer span.End()

	filter := bson.M{
		"authentic_source": authenticSource,
		"attributes":       attributes,
	}

	var result model.IdentityMapping
	if err := c.MappingColl.FindOne(ctx, filter).Decode(&result); err != nil {
		span.SetStatus(codes.Error, err.Error())
		if err == mongo.ErrNoDocuments {
			return "", ErrNoDocuments
		}
		return "", err
	}

	return result.Identifier, nil
}

// UpdateIdentityMapping updates the attributes for an existing mapping.
func (c *VCDatastoreV2Coll) UpdateIdentityMapping(ctx context.Context, authenticSource, identifier string, attributes map[string]string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:updateIdentityMapping")
	defer span.End()

	filter := bson.M{
		"authentic_source": authenticSource,
		"identifier":       identifier,
	}
	update := bson.M{
		"$set": bson.M{"attributes": attributes},
	}

	result, err := c.MappingColl.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNoDocuments
	}

	return nil
}

// DeleteIdentityMapping removes an identity mapping.
func (c *VCDatastoreV2Coll) DeleteIdentityMapping(ctx context.Context, authenticSource, identifier string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:deleteIdentityMapping")
	defer span.End()

	filter := bson.M{
		"authentic_source": authenticSource,
		"identifier":       identifier,
	}

	result, err := c.MappingColl.DeleteOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if result.DeletedCount == 0 {
		return ErrNoDocuments
	}

	return nil
}

// SaveDocument saves a v2 document. Generates DocumentID (UUIDv7) if empty.
func (c *VCDatastoreV2Coll) SaveDocument(ctx context.Context, doc *model.V2Document) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:saveDocument")
	defer span.End()

	if doc.Meta.DocumentID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return fmt.Errorf("failed to generate UUIDv7: %w", err)
		}
		doc.Meta.DocumentID = id.String()
	}

	if _, err := c.DocColl.InsertOne(ctx, doc); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// GetDocument retrieves a single document by its unique key.
func (c *VCDatastoreV2Coll) GetDocument(ctx context.Context, authenticSource, scope, documentID string) (*model.V2Document, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:getDocument")
	defer span.End()

	filter := bson.M{
		"meta.authentic_source": authenticSource,
		"meta.scope":            scope,
		"meta.document_id":      documentID,
	}

	var result model.V2Document
	if err := c.DocColl.FindOne(ctx, filter).Decode(&result); err != nil {
		span.SetStatus(codes.Error, err.Error())
		if err == mongo.ErrNoDocuments {
			return nil, ErrNoDocuments
		}
		return nil, err
	}

	return &result, nil
}

// ListDocuments lists documents matching an identifier within an authentic source, optionally filtered by scope.
func (c *VCDatastoreV2Coll) ListDocuments(ctx context.Context, authenticSource, identifier, scope string) ([]*model.V2Document, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:listDocuments")
	defer span.End()

	filter := bson.M{
		"meta.authentic_source": authenticSource,
		"identities":            identifier,
	}
	if scope != "" {
		filter["meta.scope"] = scope
	}

	cursor, err := c.DocColl.Find(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []*model.V2Document
	if err := cursor.All(ctx, &results); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return results, nil
}

// DeleteDocument removes a document by its unique key.
func (c *VCDatastoreV2Coll) DeleteDocument(ctx context.Context, authenticSource, scope, documentID string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:deleteDocument")
	defer span.End()

	filter := bson.M{
		"meta.authentic_source": authenticSource,
		"meta.scope":            scope,
		"meta.document_id":      documentID,
	}

	result, err := c.DocColl.DeleteOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if result.DeletedCount == 0 {
		return ErrNoDocuments
	}

	return nil
}

// ResolveAndGetDocuments resolves identity attributes to an identifier, then fetches matching documents.
func (c *VCDatastoreV2Coll) ResolveAndGetDocuments(ctx context.Context, authenticSource, scope string, attributes map[string]string) ([]*model.V2Document, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore_v2:resolveAndGetDocuments")
	defer span.End()

	identifier, err := c.GetIdentityMapping(ctx, authenticSource, attributes)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("identity resolution failed: %w", err)
	}

	docs, err := c.ListDocuments(ctx, authenticSource, identifier, scope)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return docs, nil
}
