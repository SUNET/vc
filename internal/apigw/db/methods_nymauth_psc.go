package db

import (
	"context"
	"errors"
	"time"

	"github.com/SUNET/vc/pkg/logger"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// NymAuthPSCColl is the MongoDB-backed NymAuthPSCStore.
type NymAuthPSCColl struct {
	Service    *Service
	Coll       *mongo.Collection
	ResetsColl *mongo.Collection
	log        *logger.Log
}

// NewNymAuthPSCColl creates the Mongo-backed NymAuthPSCStore.
func NewNymAuthPSCColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*NymAuthPSCColl, error) {
	c := &NymAuthPSCColl{
		log:     log,
		Service: service,
	}
	db := c.Service.MongoClient.Database("vc")
	c.Coll = db.Collection(collName)
	c.ResetsColl = db.Collection(collName + "_resets")

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// createIndex builds the two unique indexes the store's rules rest on.
//
// They are not an optimisation. The one on subject_key is what makes
// "one commitment per subject" a property of the database rather than
// of the order two concurrent requests happened to run in, and the one
// on (subject_key, evidence_ref) is what makes a reset idempotent.
func (c *NymAuthPSCColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:nymauth_psc:createIndex")
	defer span.End()

	if _, err := c.Coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{bson.E{Key: "subject_key", Value: 1}},
		Options: options.Index().SetName("nymauth_psc_subject_uniq").SetUnique(true),
	}); err != nil {
		return err
	}
	_, err := c.ResetsColl.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "subject_key", Value: 1},
			bson.E{Key: "evidence_ref", Value: 1},
		},
		Options: options.Index().SetName("nymauth_psc_reset_evidence_uniq").SetUnique(true),
	})
	return err
}

// Accept inserts the commitment if the subject has none, then reads
// back what is stored and compares. See the SQL implementation for why
// this order and not the other.
func (c *NymAuthPSCColl) Accept(ctx context.Context, subjectKey, psc string, now time.Time) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:nymauth_psc:accept")
	defer span.End()

	if err := checkPSCArgs(subjectKey, psc); err != nil {
		return err
	}

	_, err := c.Coll.UpdateOne(ctx,
		bson.M{"subject_key": subjectKey},
		bson.M{"$setOnInsert": bson.M{
			"subject_key": subjectKey,
			"psc":         psc,
			"acceptance":  uuid.NewString(),
			"accepted_at": now.UTC(),
		}},
		options.UpdateOne().SetUpsert(true),
	)
	if err != nil && !mongo.IsDuplicateKeyError(err) {
		// A duplicate key here is the race this is written for: the
		// other request's upsert inserted first. Its value is read
		// below like any other, so the outcome is the same as if this
		// request had arrived second in the first place.
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	stored, err := c.Get(ctx, subjectKey)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if stored == nil {
		return errors.New("nymauth: the commitment was neither stored nor rejected")
	}
	if stored.PSC != psc {
		return ErrPSCConflict
	}
	return nil
}

// Get returns the subject's record, or nil.
func (c *NymAuthPSCColl) Get(ctx context.Context, subjectKey string) (*NymAuthPSCRecord, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:nymauth_psc:get")
	defer span.End()

	var record NymAuthPSCRecord
	if err := c.Coll.FindOne(ctx, bson.M{"subject_key": subjectKey}).Decode(&record); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return &record, nil
}

// Reset writes the audit row and removes the record.
//
// The audit row goes FIRST, and its unique index is what makes the pair
// safe without a transaction: if the insert succeeds this call owns the
// reset, and if it reports a duplicate then another call already did
// it and this one has nothing left to do. Removing the record first
// would leave a window in which a reset had happened with nothing
// saying who approved it.
func (c *NymAuthPSCColl) Reset(ctx context.Context, subjectKey, approvedBy, evidenceRef string, now time.Time) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:nymauth_psc:reset")
	defer span.End()

	if err := checkHexDigest(subjectKey, "subject key"); err != nil {
		return err
	}
	if approvedBy == "" || evidenceRef == "" {
		return errors.New("nymauth: a reset needs an approving operator and an evidence reference")
	}

	record, err := c.Get(ctx, subjectKey)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	existing, err := c.resetByEvidence(ctx, subjectKey, evidenceRef)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if existing != nil {
		// This evidence has already been used, so the trail is written
		// and this call must not write a second row. It may still have
		// work to do: without transactions the audit insert and the
		// record removal are two operations, and a crash between them
		// leaves the audited commitment in place. Finishing it is what
		// makes the retry a retry rather than a no-op reporting success
		// for a reset that never completed.
		return c.removeAuditedRecord(ctx, subjectKey, existing.ResetAcceptance, record)
	}
	if record == nil {
		return ErrPSCNoRecord
	}

	_, err = c.ResetsColl.InsertOne(ctx, NymAuthPSCReset{
		SubjectKey:      subjectKey,
		EvidenceRef:     evidenceRef,
		ResetOf:         ResetOf(record.PSC),
		ResetAcceptance: record.Acceptance,
		ApprovedBy:      approvedBy,
		ApprovedAt:      now.UTC(),
	})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			// Another call won the race for this evidence; it owns the
			// removal and this one has nothing left to do.
			return nil
		}
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return c.removeAuditedRecord(ctx, subjectKey, record.Acceptance, record)
}

// resetByEvidence returns the audit row for this evidence, or nil.
func (c *NymAuthPSCColl) resetByEvidence(ctx context.Context, subjectKey, evidenceRef string) (*NymAuthPSCReset, error) {
	var row NymAuthPSCReset
	err := c.ResetsColl.FindOne(ctx, bson.M{"subject_key": subjectKey, "evidence_ref": evidenceRef}).Decode(&row)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return &row, nil
}

// removeAuditedRecord deletes the ACCEPTANCE the trail says was reset,
// and only that one.
//
// The predicate names the acceptance, not the commitment and not just
// the subject. A subject recovering may well re-present the SAME
// commitment - the same wallet, the same seed, a reset that turned out
// to be unnecessary - and matching on the commitment would then let a
// replayed reset delete that new record while believing it was
// finishing an interrupted one. From the subject key, and even from
// the commitment, those two cases are indistinguishable; from the
// acceptance they are not.
func (c *NymAuthPSCColl) removeAuditedRecord(ctx context.Context, subjectKey, acceptance string, record *NymAuthPSCRecord) error {
	if !completesAnInterruptedReset(acceptance, record) {
		return nil
	}
	_, err := c.Coll.DeleteOne(ctx, bson.M{"subject_key": subjectKey, "acceptance": acceptance})
	return err
}

// Resets returns the subject's audit trail, oldest first.
func (c *NymAuthPSCColl) Resets(ctx context.Context, subjectKey string) ([]NymAuthPSCReset, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:nymauth_psc:resets")
	defer span.End()

	cursor, err := c.ResetsColl.Find(ctx, bson.M{"subject_key": subjectKey},
		options.Find().SetSort(bson.D{bson.E{Key: "approved_at", Value: 1}, bson.E{Key: "evidence_ref", Value: 1}}))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	out := []NymAuthPSCReset{}
	if err := cursor.All(ctx, &out); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return out, nil
}

// Erase removes the record and its audit rows together.
func (c *NymAuthPSCColl) Erase(ctx context.Context, subjectKey string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:nymauth_psc:erase")
	defer span.End()

	// The RECORD first. A reset needs a record to act on, so once it is
	// gone no new audit row can be created for this subject. Deleting
	// the trail first left a window in which a concurrent reset read
	// the record, inserted its row after this delete, and erasure
	// returned success with that row retained - a kept identifier for
	// a subject who asked to be forgotten.
	if _, err := c.Coll.DeleteOne(ctx, bson.M{"subject_key": subjectKey}); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	for range 2 {
		// Twice, for a reset that read the record before the delete
		// above and inserted its row after the first sweep. Without
		// transactions the window cannot be closed, only narrowed to
		// requiring a reset to span both sweeps - and this is a subject
		// exercising erasure, where a leftover row is not an acceptable
		// remainder.
		if _, err := c.ResetsColl.DeleteMany(ctx, bson.M{"subject_key": subjectKey}); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return err
		}
	}
	return nil
}
