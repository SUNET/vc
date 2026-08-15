package db

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"time"

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

	// Compound index for ResolveMapping queries that filter on
	// authentic_source + attributes (given_name, family_name, birth_date).
	// Without this index, every identity resolution does a collection scan.
	indexAttributeLookup := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "authentic_source", Value: 1},
			bson.E{Key: "attributes.family_name", Value: 1},
			bson.E{Key: "attributes.given_name", Value: 1},
			bson.E{Key: "attributes.birth_date", Value: 1},
		},
		Options: options.Index().SetName("attribute_lookup"),
	}

	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexUnique, indexAttributeLookup})
	if err != nil {
		return err
	}
	return nil
}

// Count returns the (possibly approximate) number of identity mappings.
func (c *IdentityMappingsColl) Count(ctx context.Context) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:count")
	defer span.End()

	count, err := c.Coll.EstimatedDocumentCount(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}
	return count, nil
}

// CreateMapping creates a new identity mapping
func (c *IdentityMappingsColl) CreateMapping(ctx context.Context, mapping *model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:createMapping")
	defer span.End()

	mapping.CreatedAt = time.Now().UTC()

	_, err := c.Coll.InsertOne(ctx, mapping)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// CreateMappings creates multiple identity mappings using bulk insert
func (c *IdentityMappingsColl) CreateMappings(ctx context.Context, mappings []*model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:createMappings")
	defer span.End()

	now := time.Now().UTC()
	inserts := make([]any, 0, len(mappings))
	for _, m := range mappings {
		m.CreatedAt = now
		inserts = append(inserts, m)
	}

	_, err := c.Coll.InsertMany(ctx, inserts)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// EnsureMapping creates an identity mapping only if it does not already exist.
// If a record with the same (authentic_source, authentic_source_person_id) already exists, it is left unchanged.
func (c *IdentityMappingsColl) EnsureMapping(ctx context.Context, mapping *model.IdentityMapping) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:ensureMapping")
	defer span.End()

	filter := bson.M{
		"authentic_source":           mapping.AuthenticSource,
		"authentic_source_person_id": mapping.AuthenticSourcePersonID,
	}

	update := bson.M{
		"$setOnInsert": bson.M{
			"authentic_source":           mapping.AuthenticSource,
			"authentic_source_person_id": mapping.AuthenticSourcePersonID,
			"attributes":                 mapping.Attributes,
			"created_at":                 time.Now().UTC(),
		},
	}

	opts := options.UpdateOne().SetUpsert(true)

	_, err := c.Coll.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// ResolveMappingQuery is the query for resolving attributes to an authentic_source_person_id
type ResolveMappingQuery struct {
	AuthenticSource string            `json:"authentic_source"`
	Attributes      map[string]string `json:"attributes"`
}

// ResolveMapping resolves identity attributes to an authentic_source_person_id.
func (c *IdentityMappingsColl) ResolveMapping(ctx context.Context, query *ResolveMappingQuery) (string, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:resolveMapping")
	defer span.End()

	conditions := []bson.M{}
	if query.AuthenticSource != "" {
		conditions = append(conditions, bson.M{
			"authentic_source": bson.M{"$eq": query.AuthenticSource},
		})
	}

	for key, value := range query.Attributes {
		conditions = append(conditions, bson.M{
			"attributes." + key: bson.M{"$eq": value},
		})
	}

	if len(conditions) == 0 {
		span.SetStatus(codes.Error, helpers.ErrNoIdentityFound.Error())
		return "", helpers.ErrNoIdentityFound
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

// SearchMappingsQuery is the query for searching identity mappings
type SearchMappingsQuery struct {
	Search                  string   `json:"search"`
	AuthenticSource         string   `json:"authentic_source"`
	Limit                   int64    `json:"limit"`
	AllowedAuthenticSources []string `json:"-"`
}

// SearchMappings returns identity mappings matching a text search or filters, with a limit
func (c *IdentityMappingsColl) SearchMappings(ctx context.Context, query *SearchMappingsQuery) ([]*model.IdentityMapping, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:identities:searchMappings")
	defer span.End()

	filter := bson.M{}
	if query.AuthenticSource != "" {
		if len(query.AllowedAuthenticSources) > 0 && !slices.Contains(query.AllowedAuthenticSources, query.AuthenticSource) {
			return []*model.IdentityMapping{}, nil
		}
		filter["authentic_source"] = bson.M{"$eq": query.AuthenticSource}
	} else if len(query.AllowedAuthenticSources) > 0 {
		filter["authentic_source"] = bson.M{"$in": query.AllowedAuthenticSources}
	}
	if query.Search != "" {
		searchRegex := bson.M{"$regex": regexp.QuoteMeta(query.Search), "$options": "i"}
		filter["$or"] = bson.A{
			bson.M{"authentic_source_person_id": searchRegex},
			bson.M{"authentic_source": searchRegex},
			bson.M{"attributes.family_name": searchRegex},
			bson.M{"attributes.given_name": searchRegex},
			bson.M{"attributes.birth_date": searchRegex},
		}
	}

	limit := int64(50)
	if query.Limit > 0 && query.Limit <= 200 {
		limit = query.Limit
	}

	opts := options.Find().SetLimit(limit).SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := c.Coll.Find(ctx, filter, opts)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	var res []*model.IdentityMapping
	if err := cursor.All(ctx, &res); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return res, nil
}
