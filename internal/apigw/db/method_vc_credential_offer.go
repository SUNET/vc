package db

import (
	"context"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vci"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

type VCCredentialOfferColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

func NewCredentialOfferColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*VCCredentialOfferColl, error) {
	c := &VCCredentialOfferColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.MongoClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *VCCredentialOfferColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:credential_offer:createIndex")
	defer span.End()

	indexCredentialOfferURIUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "uuid", Value: 1},
		},
		Options: options.Index().SetName("credential_offer_uuid_uniq").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexCredentialOfferURIUniq})
	if err != nil {
		return err
	}
	return nil
}

type CredentialOfferDocument struct {
	UUID                      string                               `bson:"uuid"`
	CredentialOfferParameters openid4vci.CredentialOfferParameters `bson:"credential_offer_parameters"`
}

func (c *VCCredentialOfferColl) Save(ctx context.Context, doc *CredentialOfferDocument) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:credential_offer:save")
	defer span.End()

	c.log.Info("Saving credential offer", "uuid", doc.UUID)

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Delete deletes one code_challenge
func (c *VCCredentialOfferColl) Delete(ctx context.Context, uuid string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:credential_offer:delete")
	defer span.End()

	filter := bson.M{
		"uuid": bson.M{"$eq": uuid},
	}

	_, err := c.Coll.DeleteOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

func (c *VCCredentialOfferColl) Get(ctx context.Context, uuid string) (*CredentialOfferDocument, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:credential_offer:get")
	defer span.End()

	filter := bson.M{
		"uuid": bson.M{"$eq": uuid},
	}

	c.log.Debug("Get credential offer", "filter", filter)

	credentialOffer := &CredentialOfferDocument{}
	if err := c.Coll.FindOne(ctx, filter).Decode(credentialOffer); err != nil {
		return nil, err
	}

	return credentialOffer, nil
}
