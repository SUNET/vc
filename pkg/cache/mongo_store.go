package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoStore implements AuthContextStore using MongoDB as the backend.
// This enables horizontal scaling (HA) by sharing session state across instances.
type MongoStore struct {
	coll *mongo.Collection
}

// NewMongoStore creates a new MongoDB-backed authorization context store.
// It sets up the collection with required indexes including a TTL index for automatic expiration.
func NewMongoStore(ctx context.Context, client *mongo.Client, database, collection string, ttl time.Duration) (*MongoStore, error) {
	if client == nil {
		return nil, errors.New("mongo client cannot be nil")
	}

	coll := client.Database(database).Collection(collection)

	// Create indexes for efficient lookups
	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "session_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "request_uri", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
		{
			Keys: bson.D{{Key: "code", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
		{
			Keys: bson.D{{Key: "state", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
		{
			Keys: bson.D{{Key: "verifier_response_code", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
		{
			Keys: bson.D{{Key: "ephemeral_encryption_key_id", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
		{
			Keys: bson.D{{Key: "request_object_id", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
		{
			Keys: bson.D{{Key: "token.access_token", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
		{
			Keys: bson.D{{Key: "access_token", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
		{
			// TTL index: MongoDB automatically deletes documents after the TTL expires.
			// Uses the created_at field as the reference timestamp.
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(int32(ttl.Seconds())),
		},
	}

	if _, err := coll.Indexes().CreateMany(ctx, indexes); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	return &MongoStore{coll: coll}, nil
}

// Save stores an authorization context in MongoDB with sessionID as primary key.
func (s *MongoStore) Save(ctx context.Context, doc *AuthorizationContext) error {
	if doc == nil {
		return errors.New("document cannot be nil")
	}
	if doc.SessionID == "" {
		return errors.New("sessionID is required")
	}

	if err := doc.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if doc.CreatedAt.IsZero() {
		doc.CreatedAt = time.Now()
	}

	_, err := s.coll.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("failed to save auth context: %w", err)
	}

	return nil
}

// Create is an alias for Save.
func (s *MongoStore) Create(ctx context.Context, doc *AuthorizationContext) error {
	return s.Save(ctx, doc)
}

// Get retrieves an authorization context by query fields.
func (s *MongoStore) Get(ctx context.Context, query *AuthorizationContext) (*AuthorizationContext, error) {
	if query == nil {
		return nil, errors.New("query cannot be nil")
	}

	filter := s.buildFilter(query)
	if filter == nil {
		return nil, errors.New("query must have at least one search field")
	}

	var result AuthorizationContext
	err := s.coll.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrNoDocuments
		}
		return nil, fmt.Errorf("failed to get auth context: %w", err)
	}

	return &result, nil
}

// GetByID retrieves an authorization context by session ID.
func (s *MongoStore) GetByID(ctx context.Context, id string) (*AuthorizationContext, error) {
	if id == "" {
		return nil, errors.New("id cannot be empty")
	}

	var result AuthorizationContext
	err := s.coll.FindOne(ctx, bson.M{"session_id": id}).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrNoDocuments
		}
		return nil, fmt.Errorf("failed to get auth context by id: %w", err)
	}

	return &result, nil
}

// GetByAuthorizationCode retrieves an authorization context by authorization code.
func (s *MongoStore) GetByAuthorizationCode(ctx context.Context, code string) (*AuthorizationContext, error) {
	if code == "" {
		return nil, errors.New("code cannot be empty")
	}

	var result AuthorizationContext
	err := s.coll.FindOne(ctx, bson.M{"code": code}).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrNoDocuments
		}
		return nil, fmt.Errorf("failed to get auth context by code: %w", err)
	}

	return &result, nil
}

// GetByAccessToken retrieves an authorization context by access token.
func (s *MongoStore) GetByAccessToken(ctx context.Context, token string) (*AuthorizationContext, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}

	filter := bson.M{
		"$or": bson.A{
			bson.M{"token.access_token": token},
			bson.M{"access_token": token},
		},
	}

	var result AuthorizationContext
	err := s.coll.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrNoDocuments
		}
		return nil, fmt.Errorf("failed to get auth context by access token: %w", err)
	}

	return &result, nil
}

// GetWithAccessToken retrieves an authorization context by access token (legacy method).
func (s *MongoStore) GetWithAccessToken(ctx context.Context, token string) (*AuthorizationContext, error) {
	return s.GetByAccessToken(ctx, token)
}

// Update updates an existing authorization context.
func (s *MongoStore) Update(ctx context.Context, doc *AuthorizationContext) error {
	if doc == nil {
		return errors.New("document cannot be nil")
	}
	if doc.SessionID == "" {
		return errors.New("sessionID is required")
	}

	if err := doc.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	result, err := s.coll.ReplaceOne(ctx, bson.M{"session_id": doc.SessionID}, doc)
	if err != nil {
		return fmt.Errorf("failed to update auth context: %w", err)
	}
	if result.MatchedCount == 0 {
		return ErrNoDocuments
	}

	return nil
}

// Delete removes an authorization context by session ID.
func (s *MongoStore) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("id cannot be empty")
	}

	_, err := s.coll.DeleteOne(ctx, bson.M{"session_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete auth context: %w", err)
	}

	return nil
}

// ForfeitAuthorizationCode marks an authorization code as used.
func (s *MongoStore) ForfeitAuthorizationCode(ctx context.Context, query *AuthorizationContext) (*AuthorizationContext, error) {
	if query == nil {
		return nil, errors.New("query cannot be nil")
	}

	filter := s.buildFilter(query)
	if filter == nil {
		return nil, errors.New("query must have code or request_uri")
	}

	// First, find the document and check if already forfeited
	var doc AuthorizationContext
	err := s.coll.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrNoDocuments
		}
		return nil, fmt.Errorf("failed to find auth context: %w", err)
	}

	if doc.Forfeited {
		return nil, errors.New("authorization code already forfeited")
	}

	// Use findOneAndUpdate with a condition to prevent race conditions
	update := bson.M{"$set": bson.M{"forfeited": true}}
	notForfeited := bson.M{"forfeited": bson.M{"$ne": true}}

	// Combine original filter with not-forfeited condition
	atomicFilter := bson.M{"$and": bson.A{filter, notForfeited}}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var result AuthorizationContext
	err = s.coll.FindOneAndUpdate(ctx, atomicFilter, update, opts).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("authorization code already forfeited")
		}
		return nil, fmt.Errorf("failed to forfeit authorization code: %w", err)
	}

	return &result, nil
}

// MarkCodeAsForfeited marks an authorization code as forfeited by session ID.
func (s *MongoStore) MarkCodeAsForfeited(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("id cannot be empty")
	}

	result, err := s.coll.UpdateOne(ctx,
		bson.M{"session_id": id},
		bson.M{"$set": bson.M{"forfeited": true}},
	)
	if err != nil {
		return fmt.Errorf("failed to mark code as forfeited: %w", err)
	}
	if result.MatchedCount == 0 {
		return ErrNoDocuments
	}

	return nil
}

// Consent marks an authorization context as consented.
func (s *MongoStore) Consent(ctx context.Context, query *AuthorizationContext) error {
	if query == nil || query.RequestURI == "" {
		return errors.New("request_uri cannot be empty")
	}

	result, err := s.coll.UpdateOne(ctx,
		bson.M{"request_uri": query.RequestURI},
		bson.M{"$set": bson.M{"consent": true}},
	)
	if err != nil {
		return fmt.Errorf("failed to set consent: %w", err)
	}
	if result.MatchedCount == 0 {
		return ErrNoDocuments
	}

	return nil
}

// AddToken adds a token to an authorization context identified by code.
func (s *MongoStore) AddToken(ctx context.Context, code string, token *Token) error {
	if code == "" {
		return errors.New("code cannot be empty")
	}

	result, err := s.coll.UpdateOne(ctx,
		bson.M{"code": code},
		bson.M{"$set": bson.M{"token": token}},
	)
	if err != nil {
		return fmt.Errorf("failed to add token: %w", err)
	}
	if result.MatchedCount == 0 {
		return ErrNoDocuments
	}

	return nil
}

// SetAuthenticSource sets the authentic source for an authorization context.
func (s *MongoStore) SetAuthenticSource(ctx context.Context, query *AuthorizationContext, authenticSource string) error {
	if authenticSource == "" {
		return errors.New("authentic source cannot be empty")
	}
	if query == nil || query.SessionID == "" {
		return errors.New("session_id cannot be empty")
	}

	result, err := s.coll.UpdateOne(ctx,
		bson.M{"session_id": query.SessionID},
		bson.M{"$set": bson.M{"authentic_source": authenticSource}},
	)
	if err != nil {
		return fmt.Errorf("failed to set authentic source: %w", err)
	}
	if result.MatchedCount == 0 {
		return ErrNoDocuments
	}

	return nil
}

// AddIdentity adds identity information to an authorization context.
func (s *MongoStore) AddIdentity(ctx context.Context, query *AuthorizationContext, input *AuthorizationContext) error {
	if query == nil {
		return errors.New("query cannot be nil")
	}
	if input == nil || input.Identity == nil {
		return errors.New("identity cannot be nil")
	}

	filter := s.buildFilter(query)
	if filter == nil {
		return errors.New("query must have sessionID, requestURI, or ephemeralEncryptionKeyID")
	}

	update := bson.M{"$set": bson.M{
		"identity":         input.Identity,
		"vct":              input.VCT,
		"authentic_source": input.AuthenticSource,
	}}

	result, err := s.coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to add identity: %w", err)
	}
	if result.MatchedCount == 0 {
		return ErrNoDocuments
	}

	return nil
}

// buildFilter constructs a MongoDB filter from an AuthorizationContext query.
// Returns nil if no searchable fields are set.
func (s *MongoStore) buildFilter(query *AuthorizationContext) bson.M {
	if query.SessionID != "" {
		return bson.M{"session_id": query.SessionID}
	}
	if query.RequestURI != "" {
		return bson.M{"request_uri": query.RequestURI}
	}
	if query.Code != "" {
		return bson.M{"code": query.Code}
	}
	if query.State != "" {
		return bson.M{"state": query.State}
	}
	if query.VerifierResponseCode != "" {
		return bson.M{"verifier_response_code": query.VerifierResponseCode}
	}
	if query.EphemeralEncryptionKeyID != "" {
		return bson.M{"ephemeral_encryption_key_id": query.EphemeralEncryptionKeyID}
	}
	if query.RequestObjectID != "" {
		return bson.M{"request_object_id": query.RequestObjectID}
	}
	return nil
}
