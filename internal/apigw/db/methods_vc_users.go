package db

import (
	"context"
	"errors"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// VCUsersColl is the collection of the VC Auth
type VCUsersColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewUserColl creates a new VCUsersColl
func NewUserColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*VCUsersColl, error) {
	c := &VCUsersColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.MongoClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

func (c *VCUsersColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:users:createIndex")
	defer span.End()

	clientIDUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "username", Value: 1},
		},
		Options: options.Index().SetName("username_uniq").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{clientIDUniq})
	if err != nil {
		return err
	}

	return nil
}

// Save saves one user to the users collection
func (c *VCUsersColl) Save(ctx context.Context, doc *model.OAuthUsers) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:users:save")
	defer span.End()

	if err := helpers.Check(ctx, c.Service.cfg, doc, c.log); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// GetHashedPassword retrieves the hashed password for a given username
func (c *VCUsersColl) GetHashedPassword(ctx context.Context, username string) (string, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:users:grant")
	defer span.End()

	filter := bson.M{
		"username": bson.M{"$eq": username},
	}

	res := &model.OAuthUsers{}
	if err := c.Coll.FindOne(ctx, filter).Decode(&res); err != nil {
		span.SetStatus(codes.Error, err.Error())
		if err == mongo.ErrNoDocuments {
			return "", nil
		}
		return "", err
	}

	return res.Password, nil
}

func (c *VCUsersColl) GetUser(ctx context.Context, username string) (*model.OAuthUsers, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:user")
	defer span.End()

	filter := bson.M{
		"username": bson.M{"$eq": username},
	}

	res := &model.OAuthUsers{}
	if err := c.Coll.FindOne(ctx, filter).Decode(&res); err != nil {
		span.SetStatus(codes.Error, err.Error())
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return res, nil
}
