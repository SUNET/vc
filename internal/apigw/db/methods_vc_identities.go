package db

import (
	"context"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// VCIdentitiesColl is the collection for identity mappings
type VCIdentitiesColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

func (c *VCIdentitiesColl) createIndex(ctx context.Context) error {
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
func (c *VCIdentitiesColl) CreateMapping(ctx context.Context, mapping *model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:createMapping")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, mapping)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// ResolveMapping resolves identity attributes to an authentic_source_person_id.
// It queries both typed identity fields (identity.family_name, etc.) and the
// generic attributes map, using $or to match either location.
func (c *VCIdentitiesColl) ResolveMapping(ctx context.Context, query *ResolveMappingQuery) (string, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:resolveMapping")
	defer span.End()

	conditions := []bson.M{
		{"authentic_source": bson.M{"$eq": query.AuthenticSource}},
	}

	for key, value := range query.Attributes {
		// Match if the value is in the typed identity field OR in the attributes map
		conditions = append(conditions, bson.M{
			"$or": []bson.M{
				{"identity." + key: bson.M{"$eq": value}},
				{"attributes." + key: bson.M{"$eq": value}},
			},
		})
	}

	filter := bson.M{"$and": conditions}

	opts := options.FindOne().SetProjection(bson.M{
		"authentic_source_person_id": 1,
	})

	res := &model.IdentityMapping{}
	if err := c.Coll.FindOne(ctx, filter, opts).Decode(res); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return "", helpers.ErrNoIdentityFound
	}

	return res.AuthenticSourcePersonID, nil
}

// UpdateMapping updates the attributes of an existing identity mapping
func (c *VCIdentitiesColl) UpdateMapping(ctx context.Context, mapping *model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:updateMapping")
	defer span.End()

	filter := bson.M{
		"authentic_source":          bson.M{"$eq": mapping.AuthenticSource},
		"authentic_source_person_id": bson.M{"$eq": mapping.AuthenticSourcePersonID},
	}

	setFields := bson.M{"attributes": mapping.Attributes}
	if mapping.Identity != nil {
		setFields["identity"] = mapping.Identity
	}

	update := bson.M{"$set": setFields}

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

// DeleteMapping deletes an identity mapping
func (c *VCIdentitiesColl) DeleteMapping(ctx context.Context, query *DeleteMappingQuery) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:deleteMapping")
	defer span.End()

	filter := bson.M{
		"authentic_source":          bson.M{"$eq": query.AuthenticSource},
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
