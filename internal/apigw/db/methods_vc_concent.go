package db

import (
	"context"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// VCConsentColl is consent collection
type VCConsentColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

func (c *VCConsentColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:consent:createIndex")
	defer span.End()

	indexModel := mongo.IndexModel{
		Keys: bson.D{
			{
				Key: "authentic_source_person_id", Value: 1,
			},
			{
				Key: "authentic_source", Value: 1,
			},
		},
		Options: options.Index().SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return err
	}
	return nil
}

// AddConsentQuery is the query to add a consent
type AddConsentQuery struct {
	AuthenticSource         string         `json:"authentic_source" bson:"authentic_source" validate:"required"`
	AuthenticSourcePersonID string         `json:"authentic_source_person_id" bson:"authentic_source_person_id" validate:"required"`
	Consent                 *model.Consent `json:"consent" bson:"consent" validate:"required"`
}

// Add adds a consent to the collection
func (c *VCConsentColl) Add(ctx context.Context, consent *AddConsentQuery) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:consent:add")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, consent)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return helpers.ErrDuplicateKey
		}
	} else {
		return err
	}

	return nil
}

// GetConsentQuery is the query to get a consent
type GetConsentQuery struct {
	AuthenticSource         string `json:"authentic_source" bson:"authentic_source" validate:"required"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" bson:"authentic_source_person_id" validate:"required"`
}

// Get gets a consent from the collection
func (c *VCConsentColl) Get(ctx context.Context, query *GetConsentQuery) (*model.Consent, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:consent:get")
	defer span.End()

	filter := bson.M{
		"authentic_source":           bson.M{"$eq": query.AuthenticSource},
		"authentic_source_person_id": bson.M{"$eq": query.AuthenticSourcePersonID},
	}

	opts := options.FindOne().SetProjection(bson.M{
		"consent": 1,
	})

	res := &AddConsentQuery{}
	if err := c.Coll.FindOne(ctx, filter, opts).Decode(res); err != nil {
		return nil, err
	}

	return res.Consent, nil
}
