package db

import (
	"context"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// DatastoreColl is the generic collection
type DatastoreColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

func (c *DatastoreColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore:createIndex")
	defer span.End()

	indexDocumentIDInAuthenticSourceUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "meta.document_id", Value: 1},
			bson.E{Key: "meta.authentic_source", Value: 1},
			bson.E{Key: "meta.scope", Value: 1},
		},
		Options: options.Index().SetName("document_unique_within_namespace").SetUnique(true),
	}
	indexIdentityLookup := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "meta.scope", Value: 1},
			bson.E{Key: "identity_mapping_ids", Value: 1},
			bson.E{Key: "meta.authentic_source", Value: 1},
		},
		Options: options.Index().SetName("identity_lookup"),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexDocumentIDInAuthenticSourceUniq, indexIdentityLookup})
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document to the generic collection
func (c *DatastoreColl) Save(ctx context.Context, doc *model.CompleteDocument) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore:save")
	defer span.End()

	if err := helpers.Check(ctx, c.Service.cfg, doc, c.Service.log); err != nil {
		return err
	}

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return err
	}

	return nil
}

// AddIdentityQuery is the query to add document identity
type AddIdentityQuery struct {
	AuthenticSource    string   `json:"authentic_source" bson:"authentic_source"`
	Scope              string   `json:"scope" bson:"scope"`
	DocumentID         string   `json:"document_id" bson:"document_id"`
	IdentityMappingIDs []string `json:"identity_mapping_ids" bson:"identity_mapping_ids"`
}

// AddIdentity adds document identity
func (c *DatastoreColl) AddIdentity(ctx context.Context, query *AddIdentityQuery) error {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.AuthenticSource},
		"meta.scope":            bson.M{"$eq": query.Scope},
		"meta.document_id":      bson.M{"$eq": query.DocumentID},
	}

	// This needs to make sure no duplicate authentic_source_person_id is added in the future
	update := bson.M{"$addToSet": bson.M{"identity_mapping_ids": bson.M{"$each": query.IdentityMappingIDs}}}

	result, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.ModifiedCount == 0 {
		return helpers.ErrNoDocumentFound
	}

	return nil
}

// DeleteIdentityQuery is the query to delete identity in document
type DeleteIdentityQuery struct {
	AuthenticSource         string `json:"authentic_source" bson:"authentic_source"`
	Scope                   string `json:"scope" bson:"scope"`
	DocumentID              string `json:"document_id" bson:"document_id"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" bson:"authentic_source_person_id"`
}

// DeleteIdentity deletes identity in document
func (c *DatastoreColl) DeleteIdentity(ctx context.Context, query *DeleteIdentityQuery) error {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.AuthenticSource},
		"meta.scope":            bson.M{"$eq": query.Scope},
		"meta.document_id":      bson.M{"$eq": query.DocumentID},
	}

	update := bson.M{"$pull": bson.M{"identity_mapping_ids": query.AuthenticSourcePersonID}}
	_, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	return nil
}

// Delete deletes a document
func (c *DatastoreColl) Delete(ctx context.Context, doc *model.MetaData) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore:delete")
	defer span.End()

	filter := bson.M{
		"meta.document_id":      bson.M{"$eq": doc.DocumentID},
		"meta.authentic_source": bson.M{"$eq": doc.AuthenticSource},
	}
	_, err := c.Coll.DeleteOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil

}

// Get return matching document if any, or error
func (c *DatastoreColl) Get(ctx context.Context, meta *model.MetaData) (*model.Document, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": meta.AuthenticSource},
		"meta.scope":            bson.M{"$eq": meta.Scope},
		"meta.document_id":      bson.M{"$eq": meta.DocumentID},
	}
	opt := options.FindOne().SetProjection(bson.M{
		"meta":          1,
		"document_data": 1,
	})

	res := &model.CompleteDocument{}
	if err := c.Coll.FindOne(ctx, filter, opt).Decode(res); err != nil {
		return nil, err
	}

	reply := &model.Document{
		Meta:         res.Meta,
		DocumentData: res.DocumentData,
	}
	return reply, nil
}

// GetByIdentity returns matching documents for a scope where any of the document's identity_mapping_ids match the provided identifier.
func (c *DatastoreColl) GetByIdentity(ctx context.Context, scope, identityMappingID string) (map[string]*model.CompleteDocument, error) {
	filter := bson.M{
		"meta.scope":            bson.M{"$eq": scope},
		"identity_mapping_ids": bson.M{"$eq": identityMappingID},
	}

	c.log.Debug("GetByIdentity", "filter", filter)

	cursor, err := c.Coll.Find(ctx, filter)
	if err != nil {
		return nil, err
	}

	res := []*model.CompleteDocument{}
	if err := cursor.All(ctx, &res); err != nil {
		return nil, err
	}

	docs := make(map[string]*model.CompleteDocument, len(res))
	for _, doc := range res {
		docs[doc.Meta.AuthenticSource] = doc
	}

	return docs, nil
}

// ListQuery is the query to get document list
type ListQuery struct {
	AuthenticSource   string `json:"authentic_source" bson:"authentic_source"`
	IdentityMappingID string `json:"identity_mapping_id" bson:"identity_mapping_id" validate:"required"`
	Scope             string `json:"scope" bson:"scope"`
	ValidFrom         int64  `json:"valid_from" bson:"valid_from"`
	ValidTo           int64  `json:"valid_to" bson:"valid_to"`
}

// List return matching documents if any, or error
func (c *DatastoreColl) List(ctx context.Context, query *ListQuery) ([]*model.DocumentList, error) {
	if err := helpers.Check(ctx, c.Service.cfg, query, c.Service.log); err != nil {
		return nil, err
	}

	filter := bson.M{}

	if query.AuthenticSource != "" {
		filter["meta.authentic_source"] = bson.M{"$eq": query.AuthenticSource}
	}

	if query.Scope != "" {
		filter["meta.scope"] = bson.M{"$eq": query.Scope}
	}

	filter["identity_mapping_ids"] = bson.M{"$eq": query.IdentityMappingID}

	cursor, err := c.Coll.Find(ctx, filter)
	if err != nil {
		return nil, err
	}

	res := []*model.DocumentList{}
	if err := cursor.All(ctx, &res); err != nil {
		return nil, err
	}

	return res, nil
}

// GetQR return matching document and return its QR code, else error
func (c *DatastoreColl) GetQR(ctx context.Context, attr *model.MetaData) (*openid4vci.QR, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": attr.AuthenticSource},
		"meta.scope":            bson.M{"$eq": attr.Scope},
		"meta.document_id":      bson.M{"$eq": attr.DocumentID},
	}
	opt := options.FindOne().SetProjection(bson.M{
		"qr": 1,
	})

	res := &model.CompleteDocument{}
	if err := c.Coll.FindOne(ctx, filter, opt).Decode(res); err != nil {
		return nil, err
	}
	return res.QR, nil
}

// Replace replaces one document
func (c *DatastoreColl) Replace(ctx context.Context, doc *model.CompleteDocument) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore:replace")
	defer span.End()

	filter := bson.M{
		"meta.document_id":      bson.M{"$eq": doc.Meta.DocumentID},
		"meta.authentic_source": bson.M{"$eq": doc.Meta.AuthenticSource},
	}

	_, err := c.Coll.ReplaceOne(ctx, filter, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	c.log.Info("updated document", "document_id", doc.Meta.DocumentID)
	return nil
}

// GetByKey retrieves a document by its natural key (authentic_source, scope, document_id)
func (c *DatastoreColl) GetByKey(ctx context.Context, authenticSource, scope, documentID string) (*model.CompleteDocument, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore:getDocumentByKey")
	defer span.End()

	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": authenticSource},
		"meta.scope":            bson.M{"$eq": scope},
		"meta.document_id":      bson.M{"$eq": documentID},
	}

	res := &model.CompleteDocument{}
	if err := c.Coll.FindOne(ctx, filter).Decode(res); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return res, nil
}

// DeleteByKey deletes a document by its natural key (authentic_source, scope, document_id)
func (c *DatastoreColl) DeleteByKey(ctx context.Context, authenticSource, scope, documentID string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore:deleteDocumentByKey")
	defer span.End()

	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": authenticSource},
		"meta.scope":            bson.M{"$eq": scope},
		"meta.document_id":      bson.M{"$eq": documentID},
	}

	result, err := c.Coll.DeleteOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if result.DeletedCount == 0 {
		return helpers.ErrNoDocumentFound
	}

	return nil
}


