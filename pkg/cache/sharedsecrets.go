package cache

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/pkg/crypto"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const sharedSecretsCollection = "ha_shared_secrets"

// SharedSecrets holds session keys that must be identical across all
// instances of a service in HA mode.
type SharedSecrets struct {
	// ServiceName is the owning service (e.g. "apigw", "verifier"). Used as _id.
	ServiceName string `bson:"_id"`
	// SessionAuthKey is the HMAC authentication key for session cookies.
	SessionAuthKey string `bson:"session_auth_key"`
	// SessionEncKey is the AES encryption key for session cookies.
	SessionEncKey string `bson:"session_enc_key"`
}

// EnsureSharedSecrets returns session keys that are guaranteed to be identical
// across every instance that calls this function with the same serviceName.
//
// When the Service is in HA mode it generates candidate keys and atomically
// inserts them into MongoDB using FindOneAndUpdate with $setOnInsert +
// upsert. If another instance races and inserts first, MongoDB returns
// that existing document instead — no conflicts.
//
// When HA is disabled it simply generates ephemeral keys.
func EnsureSharedSecrets(ctx context.Context, s *Service, serviceName string) (*SharedSecrets, error) {
	candidate, err := generateSecrets(serviceName)
	if err != nil {
		return nil, err
	}

	if !s.ha {
		// Non-HA: generate ephemeral keys (existing behaviour).
		return candidate, nil
	}

	coll := s.client.Database(s.databaseName).Collection(sharedSecretsCollection)

	// Atomic upsert: only sets values if no document exists for this _id.
	filter := bson.M{"_id": serviceName}
	update := bson.M{
		"$setOnInsert": bson.M{
			"session_auth_key": candidate.SessionAuthKey,
			"session_enc_key":  candidate.SessionEncKey,
		},
	}
	opts := options.FindOneAndUpdate().
		SetUpsert(true).
		SetReturnDocument(options.After)

	var result SharedSecrets
	if err := coll.FindOneAndUpdate(ctx, filter, update, opts).Decode(&result); err != nil {
		return nil, fmt.Errorf("shared secrets upsert for %q: %w", serviceName, err)
	}

	return &result, nil
}

func generateSecrets(serviceName string) (*SharedSecrets, error) {
	authKey, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("generate session auth key: %w", err)
	}
	encKey, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("generate session enc key: %w", err)
	}
	return &SharedSecrets{
		ServiceName:    serviceName,
		SessionAuthKey: authKey,
		SessionEncKey:  encKey,
	}, nil
}
