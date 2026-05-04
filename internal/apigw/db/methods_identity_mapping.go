package db

import (
	"context"
	"errors"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// IdentityMappingsColl is the collection for identity mappings
type IdentityMappingsColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

func (c *IdentityMappingsColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:createIndex")
	defer span.End()

	indexUnique := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "authentic_source", Value: 1},
			bson.E{Key: "authentic_source_person_id", Value: 1},
		},
		Options: options.Index().SetName("identity_unique").SetUnique(true),
	}

	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexUnique})
	if err != nil {
		return err
	}
	return nil
}

// CreateMapping creates a new identity mapping
func (c *IdentityMappingsColl) CreateMapping(ctx context.Context, mapping *model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:createMapping")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, mapping)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// ResolveMappingQuery is the query for resolving attributes to an authentic_source_person_id
type ResolveMappingQuery struct {
	AuthenticSource string         `json:"authentic_source"`
	Attributes      map[string]any `json:"attributes"`
}

// ResolveMapping resolves identity attributes to an authentic_source_person_id.
func (c *IdentityMappingsColl) ResolveMapping(ctx context.Context, query *ResolveMappingQuery) (string, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:resolveMapping")
	defer span.End()

	conditions := []bson.M{
		{"authentic_source": bson.M{"$eq": query.AuthenticSource}},
	}

	for key, value := range query.Attributes {
		conditions = append(conditions, bson.M{
			"attributes." + key: bson.M{"$eq": value},
		})
	}

	filter := bson.M{"$and": conditions}

	opts := options.FindOne().SetProjection(bson.M{
		"authentic_source_person_id": 1,
	})

	res := &model.IdentityMapping{}
	if err := c.Coll.FindOne(ctx, filter, opts).Decode(res); err != nil {
		span.SetStatus(codes.Error, err.Error())
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", helpers.ErrNoIdentityFound
		}
		return "", err
	}

	return res.AuthenticSourcePersonID, nil
}

// UpdateMapping updates the attributes of an existing identity mapping
func (c *IdentityMappingsColl) UpdateMapping(ctx context.Context, mapping *model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:updateMapping")
	defer span.End()

	filter := bson.M{
		"authentic_source":           bson.M{"$eq": mapping.AuthenticSource},
		"authentic_source_person_id": bson.M{"$eq": mapping.AuthenticSourcePersonID},
	}

	update := bson.M{"$set": bson.M{"attributes": mapping.Attributes}}

	result, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if result.MatchedCount == 0 {
		return helpers.ErrNoIdentityFound
	}

	return nil
}

// DeleteMappingQuery is the query for deleting an identity mapping
type DeleteMappingQuery struct {
	AuthenticSource         string `json:"authentic_source"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// DeleteMapping deletes an identity mapping
func (c *IdentityMappingsColl) DeleteMapping(ctx context.Context, query *DeleteMappingQuery) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:deleteMapping")
	defer span.End()

	filter := bson.M{
		"authentic_source":           bson.M{"$eq": query.AuthenticSource},
		"authentic_source_person_id": bson.M{"$eq": query.AuthenticSourcePersonID},
	}

	result, err := c.Coll.DeleteOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if result.DeletedCount == 0 {
		return helpers.ErrNoIdentityFound
	}

	return nil
}
