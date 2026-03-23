package db

import (
	"context"
	"fmt"
	"math/rand/v2"
	"vc/pkg/logger"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

const maxRandomLimit int = 3

// TokenStatusListColl is the collection for status list
type TokenStatusListColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// TokenStatusListDoc represents a document in the Token Status List document
type TokenStatusListDoc struct {
	Index   int64 `bson:"index"`
	Status  uint8 `bson:"status"`
	Decoy   bool  `bson:"decoy"`
	Section int64 `bson:"section"`
}

// NewTokenStatusListColl creates a new Token Status List coll
func NewTokenStatusListColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*TokenStatusListColl, error) {
	c := &TokenStatusListColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.MongoClient.Database(databaseName).Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

// InitializeIfEmpty checks if the collection is empty and initializes it with sample data
func (c *TokenStatusListColl) InitializeIfEmpty(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list:initializeIfEmpty")
	defer span.End()

	count, err := c.CountDocs(ctx, bson.M{})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if count > 0 {
		c.log.Info("Status list collection already initialized", "documents", count)
		return nil
	}

	c.log.Info("Status list collection is empty, initializing section 0 with decoys")

	// Create section 0 with decoy entries, use config section size
	sectionSize := c.Service.cfg.Registry.TokenStatusLists.SectionSize
	if err := c.CreateNewSection(ctx, 0, sectionSize); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	c.log.Info("Status list collection initialized with section 0")
	return nil
}

func (c *TokenStatusListColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list:createIndex")
	defer span.End()

	indexUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "index", Value: 1},
			bson.E{Key: "section", Value: 1},
		},
		Options: options.Index().SetName("index_uniq").SetUnique(true),
	}
	indexDecoyLookup := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "section", Value: 1},
			bson.E{Key: "decoy", Value: 1},
		},
		Options: options.Index().SetName("decoy_lookup"),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexUniq, indexDecoyLookup})
	if err != nil {
		return err
	}

	return nil
}

// CountDocs counts documents matching the filter
func (c *TokenStatusListColl) CountDocs(ctx context.Context, filter bson.M) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list:countDocs")
	defer span.End()

	count, err := c.Coll.CountDocuments(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}

	return count, nil
}

// FindOne finds a single status entry by section and index
func (c *TokenStatusListColl) FindOne(ctx context.Context, section, index int64) (*TokenStatusListDoc, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list:findOne")
	defer span.End()

	filter := bson.M{"section": section, "index": index}

	var doc TokenStatusListDoc
	err := c.Coll.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant find status entry", "section", section, "index", index)
		return nil, err
	}

	return &doc, nil
}

// CreateNewSection creates a new section with decoy entries.
// If sectionSize is 0 or negative, it defaults to 500,000.
func (c *TokenStatusListColl) CreateNewSection(ctx context.Context, section int64, sectionSize int64) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list:createNewSection")
	defer span.End()

	// Default to 500,000 if not set
	if sectionSize <= 0 {
		sectionSize = 500000
	}

	docs := []*TokenStatusListDoc{}
	for i := int64(0); i < sectionSize; i++ {
		docs = append(docs, &TokenStatusListDoc{
			Index:   i,
			Status:  uint8(rand.IntN(maxRandomLimit)),
			Decoy:   true,
			Section: int64(section),
		})
	}

	c.log.Debug("createNewSection", "number of decoys", len(docs))
	_, err := c.Coll.InsertMany(ctx, docs)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant pre-seed section", "section", section)
		return err
	}

	return nil
}

func (c *TokenStatusListColl) getRandomDecoys(ctx context.Context, section int64) ([]TokenStatusListDoc, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list:getRandomDecoyIndexes")
	defer span.End()

	sectionSize := c.Service.cfg.Registry.TokenStatusLists.SectionSize
	if sectionSize <= 0 {
		sectionSize = 1000000
	}

	// Generate random indices and look them up directly via the {index, section} unique index.
	// This is O(n) index seeks instead of O(sectionSize) collection scan from $match + $sample.
	const want = 10
	const maxAttempts = 50
	var docs []TokenStatusListDoc
	seen := make(map[int64]bool, maxAttempts)

	for attempt := 0; len(docs) < want && attempt < maxAttempts; attempt++ {
		idx := rand.Int64N(sectionSize)
		if seen[idx] {
			continue
		}
		seen[idx] = true

		var doc TokenStatusListDoc
		err := c.Coll.FindOne(ctx, bson.M{"index": idx, "section": section}).Decode(&doc)
		if err != nil {
			continue
		}
		if !doc.Decoy {
			continue // skip already-allocated entries
		}
		docs = append(docs, doc)
	}

	if len(docs) == 0 {
		return nil, fmt.Errorf("no decoy entries found in section %d", section)
	}

	return docs, nil
}

// Add adds a new status to the status list collection, return index of the added status or an error
func (c *TokenStatusListColl) Add(ctx context.Context, section int64, status uint8) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list:add")
	defer span.End()

	decoys, err := c.getRandomDecoys(ctx, section)
	if err != nil {
		return 0, err
	}

	c.log.Debug("add", "decoys", decoys)

	doc := &TokenStatusListDoc{
		Index:   decoys[rand.IntN(len(decoys))].Index,
		Status:  status,
		Decoy:   false,
		Section: section,
	}

	// Batch all updates (real entry + noise decoys) into a single BulkWrite
	// to avoid sequential round-trips to MongoDB.
	models := make([]mongo.WriteModel, 0, len(decoys))

	// The real status entry
	models = append(models, mongo.NewUpdateOneModel().
		SetFilter(bson.M{"index": doc.Index, "section": doc.Section}).
		SetUpdate(bson.M{"$set": doc}))

	// Noise updates for the remaining decoys
	for _, decoy := range decoys {
		if decoy.Index == doc.Index {
			continue
		}
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.M{"index": decoy.Index, "section": section}).
			SetUpdate(bson.M{"$set": bson.M{"status": rand.IntN(maxRandomLimit)}}))
	}

	_, err = c.Coll.BulkWrite(ctx, models)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant add status with noise updates")
		return 0, err
	}

	return doc.Index, nil
}

// GetAllStatusesForSection retrieves all status entries for a given section, ordered by index.
// Returns a slice of status values (uint8) suitable for encoding into a Status List Token.
func (c *TokenStatusListColl) GetAllStatusesForSection(ctx context.Context, section int64) ([]uint8, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list:getAllStatusesForSection")
	defer span.End()

	filter := bson.M{"section": section}
	opts := options.Find().SetSort(bson.D{{Key: "index", Value: 1}})

	cursor, err := c.Coll.Find(ctx, filter, opts)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant get statuses for section", "section", section)
		return nil, err
	}
	defer cursor.Close(ctx)

	var docs []TokenStatusListDoc
	if err = cursor.All(ctx, &docs); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant decode statuses", "section", section)
		return nil, err
	}

	statuses := make([]uint8, len(docs))
	for i, doc := range docs {
		statuses[i] = doc.Status
	}

	return statuses, nil
}

// UpdateStatus updates the status of an existing entry at the given section and index.
func (c *TokenStatusListColl) UpdateStatus(ctx context.Context, section int64, index int64, status uint8) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:token_status_list:updateStatus")
	defer span.End()

	filter := bson.M{"section": section, "index": index}
	update := bson.M{"$set": bson.M{"status": status}}

	result, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant update status", "section", section, "index", index)
		return err
	}

	if result.MatchedCount == 0 {
		c.log.Info("no document found to update", "section", section, "index", index)
	}

	return nil
}
