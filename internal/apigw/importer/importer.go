package importer

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// gzipMagic is the two-byte header that prefixes every gzip stream (RFC 1952).
var gzipMagic = []byte{0x1f, 0x8b}

// readBootstrapFile reads a bootstrap file, transparently decompressing it when
// the content is gzip-encoded. This lets large fixtures ship compressed (e.g.
// to stay under Fly's inlined-file size limit) without changing callers.
func readBootstrapFile(path string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(data, gzipMagic) {
		return data, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip reader: %w", err)
	}
	defer zr.Close()
	decompressed, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	return decompressed, nil
}

// RunDocuments imports JSON fixture data from the configured file paths into the datastore.
// Each document is imported only if one with the same natural key is not already
// present, so adding a new fixture (or a whole new scope) to an existing
// deployment imports just the missing documents instead of being skipped.
func RunDocuments(ctx context.Context, cfg *model.DatastoreImport, dbService *db.Service, log *logger.Log) error {
	log = log.New("importer")

	for _, path := range cfg.FilePaths {
		name := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".gz"), ".json")

		if err := importDocuments(ctx, path, name, cfg.Users, cfg.ReplaceExisting, dbService.DatastoreColl, log); err != nil {
			return fmt.Errorf("import documents from %s: %w", filepath.Base(path), err)
		}
	}

	log.Info("Document import complete")
	return nil
}

func importDocuments(ctx context.Context, path, name string, filterUsers []string, replaceExisting bool, store db.DatastoreStore, log *logger.Log) error {
	data, err := readBootstrapFile(path)
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
	skipped := 0
	replaced := 0
	for id, doc := range docs {
		if !shouldImport(id, filterUsers) {
			continue
		}

		present, err := documentPresent(ctx, store, doc.Meta)
		if err != nil {
			return fmt.Errorf("check document %s/%s: %w", name, id, err)
		}
		if present {
			// Shipped, generator-owned fixtures opt into replacement so corrected
			// content (e.g. regenerated validity dates) reaches deployments that
			// already hold the previous version under the same natural key.
			// Operator-edited data keeps the default insert-only behaviour
			// (replaceExisting false) and is never overwritten.
			if replaceExisting {
				if err := store.Replace(ctx, doc); err != nil {
					return fmt.Errorf("replace document %s/%s: %w", name, id, err)
				}
				replaced++
				continue
			}
			skipped++
			continue
		}

		if err := store.Save(ctx, doc); err != nil {
			// A concurrent importer may have inserted the same natural key
			// between the presence check and this Save. Re-check: if the
			// document exists now, a losing racer counts it as skipped instead
			// of aborting the whole import and leaving later fixtures unprocessed.
			if nowPresent, lookupErr := documentPresent(ctx, store, doc.Meta); lookupErr == nil && nowPresent {
				skipped++
				continue
			}
			return fmt.Errorf("save document %s/%s: %w", name, id, err)
		}
		imported++
	}

	log.Info("Imported documents", "file", filepath.Base(path), "scope", name, "imported", imported, "replaced", replaced, "skipped", skipped)
	return nil
}

// documentPresent reports whether a document with the same natural key
// (authentic_source, scope, document_id) already exists, so a re-run only
// inserts what is missing instead of overwriting existing (possibly edited)
// documents.
func documentPresent(ctx context.Context, store db.DatastoreStore, meta *model.MetaData) (bool, error) {
	if meta == nil {
		return false, errors.New("document has no meta")
	}
	_, err := store.GetByKey(ctx, meta.AuthenticSource, meta.Scope, meta.DocumentID)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, mongo.ErrNoDocuments) || errors.Is(err, helpers.ErrNoDocumentFound) {
		return false, nil
	}
	return false, err
}

func shouldImport(id string, users []string) bool {
	if len(users) == 0 {
		return true
	}
	return slices.Contains(users, id)
}

// RunIdentityMappings imports identity mapping data from the configured file paths.
// EnsureMapping is an insert-if-absent upsert, so re-running only adds mappings
// that are not already present and never clobbers existing attributes.
func RunIdentityMappings(ctx context.Context, cfg *model.IdentityMappingImport, dbService *db.Service, log *logger.Log) error {
	log = log.New("importer")

	for _, path := range cfg.FilePaths {
		if err := importIdentityMappings(ctx, path, cfg.Users, dbService, log); err != nil {
			return fmt.Errorf("import identity mappings from %s: %w", filepath.Base(path), err)
		}
	}

	log.Info("Identity mapping import complete")
	return nil
}

func importIdentityMappings(ctx context.Context, path string, filterUsers []string, dbService *db.Service, log *logger.Log) error {
	data, err := readBootstrapFile(path)
	if err != nil {
		return err
	}

	var mappings map[string][]*model.IdentityMapping
	if err := json.Unmarshal(data, &mappings); err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	imported := 0
	for id, personMappings := range mappings {
		if !shouldImport(id, filterUsers) {
			continue
		}
		for _, mapping := range personMappings {
			if err := dbService.IdentityMappingsColl.EnsureMapping(ctx, mapping); err != nil {
				return fmt.Errorf("ensure identity mapping %s/%s: %w", id, mapping.AuthenticSource, err)
			}
			imported++
		}
	}

	log.Info("Imported identity mappings", "file", filepath.Base(path), "count", imported)
	return nil
}
