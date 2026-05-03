package db

import (
	"context"

	"github.com/SUNET/vc/pkg/logger"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// CredentialSubjectsColl is the collection for credential subjects (person info linked to Token Status List entries)
type CredentialSubjectsColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// CredentialSubjectDoc represents a credential subject with their token status list reference
type CredentialSubjectDoc struct {
	Identifier string `bson:"identifier"`
	Section    int64  `bson:"section"`
	Index      int64  `bson:"index"`
}

// NewCredentialSubjectsColl creates a new credential subjects collection
func NewCredentialSubjectsColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*CredentialSubjectsColl, error) {
	c := &CredentialSubjectsColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.MongoClient.Database(databaseName).Collection(collName)

	if err := c.createIndexes(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

func (c *CredentialSubjectsColl) createIndexes(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:credential_subjects:createIndexes")
	defer span.End()

	// Index for searching by identifier
	identifierIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: "identifier", Value: 1},
		},
	}

	// Unique index for section+index (one subject per Token Status List entry)
	tokenStatusListIndex := mongo.IndexModel{
		Keys: bson.D{
			{Key: "section", Value: 1},
			{Key: "index", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	}

	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{identifierIndex, tokenStatusListIndex})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// Search searches for credential subjects by identifier
func (c *CredentialSubjectsColl) Search(ctx context.Context, identifier string) ([]*CredentialSubjectDoc, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:credential_subjects:search")
	defer span.End()

	filter := bson.M{}
	if identifier != "" {
		filter["identifier"] = identifier
	}

	cursor, err := c.Coll.Find(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []*CredentialSubjectDoc
	if err := cursor.All(ctx, &results); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.log.Debug("Search completed", "filter", filter, "results", len(results))
	return results, nil
}

// Add adds a new credential subject to the collection
func (c *CredentialSubjectsColl) Add(ctx context.Context, doc *CredentialSubjectDoc) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:credential_subjects:add")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	c.log.Debug("Added credential subject", "identifier", doc.Identifier, "section", doc.Section, "index", doc.Index)
	return nil
}
