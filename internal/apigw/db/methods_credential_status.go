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

// CredentialStatusEntry records which status-list entry was allocated for
// which credential subject.
//
// This is what a revocation request looks a credential up by, and the apigw
// keeps its own copy so that vc's local registry can be left out of a
// deployment entirely: with an external draft-ietf-oauth-status-list
// service configured, nothing else in the issuance path needs the registry,
// and the mapping used to be the one thing that did.
type CredentialStatusEntry struct {
	// StatusListURI is the list the entry lives in. Together with Index and
	// Backend it identifies the entry - Section does not, see below.
	StatusListURI string `bson:"status_list_uri"`
	Index         int64  `bson:"idx"`
	// Identifier is the credential subject (authentic_source_person_id).
	Identifier string `bson:"identifier"`
	// Section is meaningful only for the registry backend, which shards its
	// list. An external service has no sections and reports 0 for every
	// entry, which is why it cannot be part of the key.
	Section int64 `bson:"section"`
	// Backend names the status-list implementation that issued the entry
	// ("registry" or "status_service"). Recorded because the URI alone does
	// not identify it, and guessing at revocation time writes the status
	// into the wrong list.
	Backend string `bson:"backend"`
	// AuthenticSource and Scope are what authorization is decided against:
	// the SPOCP engine hands a caller the set of authentic sources and
	// scopes it may act on, and revocation has to be able to tell whether
	// an entry is inside that set. Without them the only thing an entry
	// could be matched on is the subject identifier the caller supplied,
	// which is the caller's own input and authorizes nothing.
	AuthenticSource string    `bson:"authentic_source,omitempty"`
	Scope           string    `bson:"scope,omitempty"`
	IssuedAt        time.Time `bson:"issued_at"`
}

// CredentialStatusColl is the Mongo-backed CredentialStatusStore.
type CredentialStatusColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewCredentialStatusColl creates the credential status entry collection.
func NewCredentialStatusColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*CredentialStatusColl, error) {
	c := &CredentialStatusColl{log: log, Service: service}
	c.Coll = c.Service.MongoClient.Database("vc").Collection(collName)
	if err := c.createIndexes(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CredentialStatusColl) createIndexes(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:credential_status:createIndexes")
	defer span.End()

	// Unique on (status_list_uri, idx, backend), mirroring the SQL primary
	// key: an entry is identified by its list, its place in it, and who
	// serves the list. Keying on (section, idx) would collide across
	// different external lists, since those all report section 0; leaving
	// backend out would let a reconfiguration in which two backends serve
	// one URI have the later upsert REPLACE the earlier mapping, routing
	// that credential's revocation to the wrong service.
	entryUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "status_list_uri", Value: 1},
			bson.E{Key: "idx", Value: 1},
			bson.E{Key: "backend", Value: 1},
		},
		Options: options.Index().SetName("credential_status_entry_uniq").SetUnique(true),
	}
	identifier := mongo.IndexModel{
		Keys:    bson.D{bson.E{Key: "identifier", Value: 1}},
		Options: options.Index().SetName("credential_status_identifier"),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{entryUniq, identifier})
	return err
}

// Save records one allocated status-list entry, replacing any existing
// record of the same entry.
func (c *CredentialStatusColl) Save(ctx context.Context, entry *CredentialStatusEntry) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:credential_status:save")
	defer span.End()

	if entry.IssuedAt.IsZero() {
		entry.IssuedAt = time.Now().UTC()
	}

	// The filter must match the unique index exactly, or an upsert that
	// misses selects a row the index then refuses to create.
	filter := bson.M{"status_list_uri": entry.StatusListURI, "idx": entry.Index, "backend": entry.Backend}
	if _, err := c.Coll.ReplaceOne(ctx, filter, entry, options.Replace().SetUpsert(true)); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Delete removes one recorded mapping, addressed by the same three columns
// the unique index uses.
func (c *CredentialStatusColl) Delete(ctx context.Context, statusListURI string, index int64, backend string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:credential_status:delete")
	defer span.End()

	filter := bson.M{"status_list_uri": statusListURI, "idx": index, "backend": backend}
	if _, err := c.Coll.DeleteOne(ctx, filter); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// SearchByIdentifier returns every status entry recorded for a subject.
func (c *CredentialStatusColl) SearchByIdentifier(ctx context.Context, identifier string) ([]*CredentialStatusEntry, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:credential_status:search")
	defer span.End()

	cursor, err := c.Coll.Find(ctx, bson.M{"identifier": identifier})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	defer func() { _ = cursor.Close(ctx) }()

	entries := []*CredentialStatusEntry{}
	if err := cursor.All(ctx, &entries); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return entries, nil
}
