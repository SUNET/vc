package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"
)

// RunDocuments imports JSON fixture data from the configured file paths into the datastore.
// It skips import if the datastore already contains data.
func RunDocuments(ctx context.Context, cfg *model.DatastoreImport, dbService *db.Service, log *logger.Log) error {
	log = log.New("importer")

	count, err := dbService.DatastoreColl.Coll.EstimatedDocumentCount(ctx)
	if err != nil {
		return fmt.Errorf("check datastore count: %w", err)
	}
	if count > 0 {
		log.Info("Datastore already contains data, skipping import", "count", count)
		return nil
	}

	for _, path := range cfg.FilePaths {
		name := strings.TrimSuffix(filepath.Base(path), ".json")

		if err := importDocuments(ctx, path, name, cfg.Users, dbService, log); err != nil {
			return fmt.Errorf("import documents from %s: %w", filepath.Base(path), err)
		}
	}

	log.Info("Document import complete")
	return nil
}

func importDocuments(ctx context.Context, path, name string, filterUsers []string, dbService *db.Service, log *logger.Log) error {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return err
	}

	var docs map[string]*model.CompleteDocument
	if err := json.Unmarshal(data, &docs); err != nil {
		// Some files use UploadRequest format (with document_data_version at top level)
		var reqs map[string]*vcclient.UploadRequest
		if err2 := json.Unmarshal(data, &reqs); err2 != nil {
			return fmt.Errorf("parse: %w", err)
		}
		docs = make(map[string]*model.CompleteDocument, len(reqs))
		for id, req := range reqs {
			docs[id] = &model.CompleteDocument{
				Meta:               req.Meta,
				IdentityMappingIDs: req.IdentityMappingIDs,
				DocumentData:       req.DocumentData,
			}
		}
	}

	imported := 0
	for id, doc := range docs {
		if !shouldImport(id, filterUsers) {
			continue
		}

		if err := dbService.DatastoreColl.Save(ctx, doc); err != nil {
			return fmt.Errorf("save document %s/%s: %w", name, id, err)
		}
		imported++
	}

	log.Info("Imported documents", "file", filepath.Base(path), "scope", name, "count", imported)
	return nil
}

func shouldImport(id string, users []string) bool {
	if len(users) == 0 {
		return true
	}
	return slices.Contains(users, id)
}
