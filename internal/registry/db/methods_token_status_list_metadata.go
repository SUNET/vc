package db

import (
	"context"
	"github.com/SUNET/vc/pkg/logger"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// TokenStatusListMetadataColl is the collection for status list metadata
type TokenStatusListMetadataColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// TokenStatusListMetadataDoc represents a document in the status list metadata collection
type TokenStatusListMetadataDoc struct {
	CurrentSection int64   `bson:"current_section"`
	Sections       []int64 `bson:"sections"`
}

// NewTokenStatusListMetadataColl creates a new StatusListMetadataColl
func NewTokenStatusListMetadataColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*TokenStatusListMetadataColl, error) {
	c := &TokenStatusListMetadataColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.MongoClient.Database(databaseName).Collection(collName)

	if err := c.initMetadataDoc(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

func (c *TokenStatusListMetadataColl) initMetadataDoc(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list_metadata:initMetadataDoc")
	defer span.End()

	doc := &TokenStatusListMetadataDoc{}

	err := c.Coll.FindOne(ctx, bson.M{}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			doc = &TokenStatusListMetadataDoc{
				CurrentSection: 0,
				Sections:       []int64{0},
			}
			_, err := c.Coll.InsertOne(ctx, doc)
			return err
		}
		return err
	}

	return nil
}

// GetCurrentSection returns the current section number
func (c *TokenStatusListMetadataColl) GetCurrentSection(ctx context.Context) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list_metadata:getCurrentSection")
	defer span.End()

	var doc TokenStatusListMetadataDoc

	err := c.Coll.FindOne(ctx, bson.M{}).Decode(&doc)
	if err != nil {
		return 0, err
	}

	return doc.CurrentSection, nil
}

// UpdateCurrentSection updates the current section and adds it to the sections list
func (c *TokenStatusListMetadataColl) UpdateCurrentSection(ctx context.Context, newSection int64) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list_metadata:updateCurrentSection")
	defer span.End()

	doc := &TokenStatusListMetadataDoc{}
	if err := c.Coll.FindOne(ctx, bson.M{}).Decode(doc); err != nil {
		return err
	}

	doc.CurrentSection = newSection
	doc.Sections = append(doc.Sections, doc.CurrentSection)

	update := bson.M{
		"$set": bson.M{
			"current_section": doc.CurrentSection,
			"sections":        doc.Sections,
		},
	}
	_, err := c.Coll.UpdateOne(ctx, bson.M{}, update)
	return err
}

// GetAllSections returns all section IDs that have been created.
// Used for Status List Aggregation (Section 9.3).
func (c *TokenStatusListMetadataColl) GetAllSections(ctx context.Context) ([]int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list_metadata:getAllSections")
	defer span.End()

	var doc TokenStatusListMetadataDoc

	err := c.Coll.FindOne(ctx, bson.M{}).Decode(&doc)
	if err != nil {
		return nil, err
	}

	return doc.Sections, nil
}
