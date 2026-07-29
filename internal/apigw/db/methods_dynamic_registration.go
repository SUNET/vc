package db

import (
	"context"
	"time"

	"github.com/SUNET/vc/pkg/logger"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// DynamicRegistrationCredentials holds OIDC dynamic client registration credentials.
type DynamicRegistrationCredentials struct {
	ClientID                string    `bson:"client_id"`
	ClientSecret            string    `bson:"client_secret"`
	RegistrationAccessToken string    `bson:"registration_access_token,omitempty"`
	RegistrationClientURI   string    `bson:"registration_client_uri,omitempty"`
	ClientSecretExpiresAt   int64     `bson:"client_secret_expires_at,omitempty"`
	RegisteredAt            time.Time `bson:"registered_at"`
}

// DynamicRegistrationColl handles persistence of dynamic client registration credentials.
type DynamicRegistrationColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewDynamicRegistrationColl creates a new collection for dynamic registration credentials.
func NewDynamicRegistrationColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*DynamicRegistrationColl, error) {
	c := &DynamicRegistrationColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.MongoClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *DynamicRegistrationColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:dynamic_registration:createIndex")
	defer span.End()

	indexClientIDUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "client_id", Value: 1},
		},
		Options: options.Index().SetName("dynamic_reg_client_id_uniq").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexClientIDUniq})
	if err != nil {
		return err
	}
	return nil
}

// Save stores or replaces dynamic registration credentials.
func (c *DynamicRegistrationColl) Save(ctx context.Context, creds *DynamicRegistrationCredentials) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:dynamic_registration:save")
	defer span.End()

	creds.RegisteredAt = time.Now()

	filter := bson.M{"client_id": creds.ClientID}
	opts := options.Replace().SetUpsert(true)

	_, err := c.Coll.ReplaceOne(ctx, filter, creds, opts)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Get returns the stored credentials, or nil if none exist.
func (c *DynamicRegistrationColl) Get(ctx context.Context) (*DynamicRegistrationCredentials, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:dynamic_registration:get")
	defer span.End()

	var creds DynamicRegistrationCredentials
	if err := c.Coll.FindOne(ctx, bson.M{}).Decode(&creds); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Check if client secret has expired
	if creds.ClientSecretExpiresAt > 0 {
		expiresAt := time.Unix(creds.ClientSecretExpiresAt, 0)
		if time.Now().After(expiresAt) {
			c.log.Info("Dynamic registration credentials expired", "client_id", creds.ClientID, "expired_at", expiresAt)
			return nil, nil
		}
	}

	return &creds, nil
}
