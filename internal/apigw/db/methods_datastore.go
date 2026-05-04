package db

import (
	"context"
	"errors"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// VCDatastoreColl is the generic collection
type VCDatastoreColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

func (c *VCDatastoreColl) createIndex(ctx context.Context) error {
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
func (c *VCDatastoreColl) Save(ctx context.Context, doc *model.CompleteDocument) error {
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

// AddDocumentIdentityQuery is the query to add document identity
type AddDocumentIdentityQuery struct {
	AuthenticSource    string   `json:"authentic_source" bson:"authentic_source"`
	Scope              string   `json:"scope" bson:"scope"`
	DocumentID         string   `json:"document_id" bson:"document_id"`
	IdentityMappingIDs []string `json:"identity_mapping_ids" bson:"identity_mapping_ids"`
}

// AddDocumentIdentity adds document identity
func (c *VCDatastoreColl) AddDocumentIdentity(ctx context.Context, query *AddDocumentIdentityQuery) error {
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

// DeleteDocumentIdentityQuery is the query to delete identity in document
type DeleteDocumentIdentityQuery struct {
	AuthenticSource         string `json:"authentic_source" bson:"authentic_source"`
	Scope                   string `json:"scope" bson:"scope"`
	DocumentID              string `json:"document_id" bson:"document_id"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" bson:"authentic_source_person_id"`
}

// DeleteDocumentIdentity deletes identity in document
func (c *VCDatastoreColl) DeleteDocumentIdentity(ctx context.Context, query *DeleteDocumentIdentityQuery) error {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.AuthenticSource},
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
func (c *VCDatastoreColl) Delete(ctx context.Context, doc *model.MetaData) error {
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

// GetDocumentQuery is the query to get document attestation
type GetDocumentQuery struct {
	Meta *model.MetaData
}

// GetDocument return matching document if any, or error
func (c *VCDatastoreColl) GetDocument(ctx context.Context, query *GetDocumentQuery) (*model.Document, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.Meta.AuthenticSource},
		"meta.document_id":      bson.M{"$eq": query.Meta.DocumentID},
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

// GetDocumentsByClaims returns matching documents for a scope where any of the
// document's identity_mapping_ids match the provided identifier.
func (c *VCDatastoreColl) GetDocumentsByClaims(ctx context.Context, scope string, identityClaims map[string]string) (map[string]*model.CompleteDocument, error) {
	filter := bson.M{
		"meta.scope": bson.M{"$eq": scope},
	}
	// identity_mapping_ids is []string — match by authentic_source_person_id if present
	if aspID, ok := identityClaims["authentic_source_person_id"]; ok {
		filter["identity_mapping_ids"] = bson.M{"$eq": aspID}
	}

	c.log.Debug("GetDocumentsByClaims", "filter", filter)

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

// DocumentListQuery is the query to get document list
type DocumentListQuery struct {
	AuthenticSource   string `json:"authentic_source" bson:"authentic_source"`
	IdentityMappingID string `json:"identity_mapping_id" bson:"identity_mapping_id" validate:"required"`
	Scope             string `json:"scope" bson:"scope"`
	ValidFrom         int64  `json:"valid_from" bson:"valid_from"`
	ValidTo           int64  `json:"valid_to" bson:"valid_to"`
}

// DocumentList return matching documents if any, or error
func (c *VCDatastoreColl) DocumentList(ctx context.Context, query *DocumentListQuery) ([]*model.DocumentList, error) {
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
func (c *VCDatastoreColl) GetQR(ctx context.Context, attr *model.MetaData) (*openid4vci.QR, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": attr.AuthenticSource},
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
func (c *VCDatastoreColl) Replace(ctx context.Context, doc *model.CompleteDocument) error {
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

// SearchDocumentsQuery the query to search for documents
type SearchDocumentsQuery struct {
	AuthenticSource   string `json:"authentic_source,omitempty" validate:"omitempty,max=1000"`
	Scope             string `json:"scope,omitempty" validate:"omitempty,max=1000"`
	DocumentID        string `json:"document_id,omitempty" validate:"omitempty,max=1000"`
	IdentityMappingID string `json:"identity_mapping_id,omitempty"`
}

// SearchDocuments search documents in datastore
//
//	@return			return matching documents, has more results (refine query), or error
//	@Description	not supported in production mode
//	@Deprecated
func (c *VCDatastoreColl) SearchDocuments(ctx context.Context, query *SearchDocumentsQuery, limit int64, fields []string, sortFields map[string]int) ([]*model.CompleteDocument, bool, error) {
	if model.BoolVal(c.Service.cfg.Common.Production, true) {
		return nil, false, errors.New("not supported in production mode")
	}

	if err := helpers.Check(ctx, c.Service.cfg, query, c.Service.log); err != nil {
		return nil, false, err
	}

	filter := buildSearchDocumentsFilter(query)

	findOptions := options.Find()
	const maxLimit = 500
	if limit == 0 {
		limit = 50
	} else if limit > maxLimit {
		limit = maxLimit
	}
	// Set one more than wanted to see if there are more results i db
	findOptions.SetLimit(limit + 1)

	if len(fields) > 0 {
		projection := bson.M{}
		for _, field := range fields {
			projection[field] = 1
		}
		findOptions.SetProjection(projection)
	}

	sort := bson.D{}
	if len(sortFields) > 0 {
		for field, order := range sortFields {
			// 1 for ascending, -1 for descending
			sort = append(sort, bson.E{Key: field, Value: order})
		}
	} else {
		sort = append(sort, bson.E{Key: "meta.document_id", Value: 1})
	}
	findOptions.SetSort(sort)

	c.log.Debug("Searching documents using", "filter", filter, "findOptions", findOptions)

	cursor, err := c.Coll.Find(ctx, filter, findOptions)
	if err != nil {
		return nil, false, err
	}

	res := []*model.CompleteDocument{}
	if err := cursor.All(ctx, &res); err != nil {
		return nil, false, err
	}

	hasMoreResults := len(res) > int(limit)
	if hasMoreResults {
		// Remove the last entry from the result to fit limit value
		res = res[:limit]
	}

	return res, hasMoreResults, nil
}

func buildSearchDocumentsFilter(query *SearchDocumentsQuery) bson.M {
	filter := bson.M{}

	if query.AuthenticSource != "" {
		filter["meta.authentic_source"] = bson.M{"$eq": query.AuthenticSource}
	}
	if query.Scope != "" {
		filter["meta.scope"] = bson.M{"$eq": query.Scope}
	}
	if query.DocumentID != "" {
		filter["meta.document_id"] = bson.M{"$eq": query.DocumentID}
	}

	if query.IdentityMappingID != "" {
		filter["identity_mapping_ids"] = bson.M{"$eq": query.IdentityMappingID}
	}

	return filter
}

// GetDocumentByKey retrieves a document by its natural key (authentic_source, scope, document_id)
func (c *VCDatastoreColl) GetDocumentByKey(ctx context.Context, authenticSource, scope, documentID string) (*model.CompleteDocument, error) {
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

// DeleteDocumentByKey deletes a document by its natural key (authentic_source, scope, document_id)
func (c *VCDatastoreColl) DeleteDocumentByKey(ctx context.Context, authenticSource, scope, documentID string) error {
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


