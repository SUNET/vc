package db

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// mongoUniqueCommitments is the Mongo backend of UniqueCommitments.
type mongoUniqueCommitments struct {
	records *mongo.Collection
	resets  *mongo.Collection
}

// NewUniqueCommitmentColl opens the Mongo unique commitment collections and
// their unique indexes.
func NewUniqueCommitmentColl(ctx context.Context, service *Service) (*UniqueCommitments, error) {
	database := service.MongoClient.Database(service.cfg.Common.Mongo.APIGWDatabaseName)
	backend := &mongoUniqueCommitments{
		records: database.Collection("unique_commitments"),
		resets:  database.Collection("unique_commitment_resets"),
	}
	key := bson.D{{Key: "scope", Value: 1}, {Key: "path", Value: 1}, {Key: "key_hash", Value: 1}}
	if _, err := backend.records.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: key, Options: options.Index().SetName("unique_commitment_key_uniq").SetUnique(true),
	}); err != nil {
		return nil, err
	}
	if _, err := backend.resets.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: append(key, bson.E{Key: "evidence_ref", Value: 1}), Options: options.Index().SetName("unique_commitment_reset_uniq").SetUnique(true),
	}); err != nil {
		return nil, err
	}
	return &UniqueCommitments{Service: service, backend: backend}, nil
}

func (m *mongoUniqueCommitments) insertCommitment(ctx context.Context, row uniqueCommitmentRow) error {
	_, err := m.records.InsertOne(ctx, row)
	if mongo.IsDuplicateKeyError(err) {
		return nil
	}
	return err
}

func (m *mongoUniqueCommitments) record(ctx context.Context, key storedKey) (uniqueCommitmentRow, error) {
	var row uniqueCommitmentRow
	if err := m.records.FindOne(ctx, key).Decode(&row); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return row, ErrNoDocuments
		}
		return row, err
	}
	return row, nil
}

func (m *mongoUniqueCommitments) keepCommitment(ctx context.Context, key storedKey, commitment string) error {
	filter := bson.M{"scope": key.Scope, "path": key.Path, "key_hash": key.KeyHash, "commitment": commitment}
	_, err := m.records.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"releasable_by": ""}})
	return err
}

func (m *mongoUniqueCommitments) takeOverCommitment(ctx context.Context, key storedKey, commitment, call string) error {
	filter := bson.M{"scope": key.Scope, "path": key.Path, "key_hash": key.KeyHash, "commitment": commitment, "releasable_by": bson.M{"$ne": ""}}
	_, err := m.records.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"releasable_by": call}})
	return err
}

func (m *mongoUniqueCommitments) releaseCommitment(ctx context.Context, key storedKey, call string) error {
	filter := bson.M{"scope": key.Scope, "path": key.Path, "key_hash": key.KeyHash, "releasable_by": call}
	_, err := m.records.DeleteOne(ctx, filter)
	return err
}

func (m *mongoUniqueCommitments) insertReset(ctx context.Context, row uniqueCommitmentResetRow) error {
	_, err := m.resets.InsertOne(ctx, row)
	if mongo.IsDuplicateKeyError(err) {
		return nil
	}
	return err
}

func (m *mongoUniqueCommitments) resetPrevious(ctx context.Context, key storedKey, evidenceRef string) (string, error) {
	var row uniqueCommitmentResetRow
	filter := bson.M{"scope": key.Scope, "path": key.Path, "key_hash": key.KeyHash, "evidence_ref": evidenceRef}
	if err := m.resets.FindOne(ctx, filter).Decode(&row); err != nil {
		return "", err
	}
	return row.PreviousSHA256, nil
}

func (m *mongoUniqueCommitments) deleteCommitment(ctx context.Context, key storedKey, commitment string) (bool, error) {
	filter := bson.M{"scope": key.Scope, "path": key.Path, "key_hash": key.KeyHash, "commitment": commitment}
	result, err := m.records.DeleteOne(ctx, filter)
	if err != nil {
		return false, err
	}
	return result.DeletedCount > 0, nil
}
