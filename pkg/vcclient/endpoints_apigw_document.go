package vcclient

import (
	"context"
	"net/http"
	"net/url"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

type documentHandler struct {
	client             *Client
	serviceBaseURL     string
	baseURL            string
	log                *logger.Log
	defaultContentType string
}

// DocumentGetQuery is the query for GetDocument
type DocumentGetQuery struct {
	AuthenticSource string `json:"authentic_source"`
	Scope           string `json:"scope"`
	DocumentID      string `json:"document_id"`
}

// Get gets a document
func (s *documentHandler) Get(ctx context.Context, query *DocumentGetQuery) (*model.Document, *http.Response, error) {
	reply := &model.Document{}
	resp, err := s.client.call(ctx, http.MethodPost, s.serviceBaseURL, s.defaultContentType, nil, reply, true, s.baseURL)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}

// DocumentListQuery is the query for ListDocument
type DocumentListQuery struct {
	AuthenticSource   string `json:"authentic_source"`
	IdentityMappingID string `json:"identity_mapping_id"`
	Scope             string `json:"scope"`
	ValidTo           int64  `json:"valid_to"`
	ValidFrom         int64  `json:"valid_from"`
}

func (s *documentHandler) List(ctx context.Context, query *DocumentListQuery) ([]model.DocumentList, *http.Response, error) {
	s.log.Info("List")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "list")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}
	reply := []model.DocumentList{}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, nil, reply, true, s.baseURL)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}

// DocumentCollectIDQuery is the query for CollectID
type DocumentCollectIDQuery struct {
	AuthenticSource string `json:"authentic_source"`
	Scope           string `json:"scope"`
	CollectID       string `json:"collect_id"`
}

// DocumentCollectIDReply is the reply for CollectID
type DocumentCollectIDReply struct {
	DocumentData any `json:"document_data"`
}

func (s *documentHandler) CollectID(ctx context.Context, query *DocumentCollectIDQuery) (*model.Document, *http.Response, error) {
	s.log.Info("CollectID")
	s.log.Debug("CollectID", "query", query)

	fullURL, err := url.JoinPath(s.serviceBaseURL, "collect_id")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}
	reply := &model.Document{}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, query, reply, true, s.baseURL)
	if err != nil {
		s.log.Error(err, "failed to call CollectID")
		return nil, resp, err
	}
	return reply, resp, nil
}

func (s *documentHandler) Search(ctx context.Context, query *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, *http.Response, error) {
	s.log.Debug("Search (Documents)")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "search")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}
	reply := &model.SearchDocumentsReply{
		Documents: []*model.CompleteDocument{},
	}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, query, reply, false, s.baseURL)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}

// DocumentDeleteQuery is the query for Delete
type DocumentDeleteQuery struct {
	AuthenticSource string `json:"authentic_source" validate:"required"`
	Scope           string `json:"scope" validate:"required"`
	DocumentID      string `json:"document_id" validate:"required"`
}

// Delete deletes a document
func (s *documentHandler) Delete(ctx context.Context, query *DocumentDeleteQuery) (*http.Response, error) {
	s.log.Info("Delete document")

	resp, err := s.client.call(ctx, http.MethodDelete, s.serviceBaseURL, s.defaultContentType, query, nil, false, s.baseURL)
	if err != nil {
		s.log.Error(err, "failed to delete document")
		return resp, err
	}
	return resp, nil
}
