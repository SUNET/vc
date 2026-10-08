package importer

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadBootstrapFile(t *testing.T) {
	payload := []byte(`{"100":{"meta":{"scope":"microcredential"}}}`)

	t.Run("plain json", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "microcredential.json")
		require.NoError(t, os.WriteFile(path, payload, 0o600))

		got, err := readBootstrapFile(path)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("gzip json yields identical bytes", func(t *testing.T) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, err := zw.Write(payload)
		require.NoError(t, err)
		require.NoError(t, zw.Close())

		path := filepath.Join(t.TempDir(), "microcredential.json.gz")
		require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))

		got, err := readBootstrapFile(path)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("corrupt gzip errors", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "broken.json.gz")
		require.NoError(t, os.WriteFile(path, append(gzipMagic, 0x00, 0x01), 0o600))

		_, err := readBootstrapFile(path)
		assert.Error(t, err)
	})
}

// fakeDatastore is a minimal in-memory db.DatastoreStore for exercising the
// per-document import logic. Only GetByKey and Save carry behaviour; the rest
// satisfy the interface and are unused by importDocuments.
type fakeDatastore struct {
	present  map[string]bool
	saved    []*model.CompleteDocument
	replaced []*model.CompleteDocument
	getByKey func(authenticSource, scope, documentID string) (*model.CompleteDocument, error)
	save     func(doc *model.CompleteDocument) error
}

func naturalKey(authenticSource, scope, documentID string) string {
	return authenticSource + "\x00" + scope + "\x00" + documentID
}

func (f *fakeDatastore) GetByKey(_ context.Context, authenticSource, scope, documentID string) (*model.CompleteDocument, error) {
	if f.getByKey != nil {
		return f.getByKey(authenticSource, scope, documentID)
	}
	if f.present[naturalKey(authenticSource, scope, documentID)] {
		return &model.CompleteDocument{}, nil
	}
	return nil, helpers.ErrNoDocumentFound
}

func (f *fakeDatastore) Save(_ context.Context, doc *model.CompleteDocument) error {
	if f.save != nil {
		return f.save(doc)
	}
	if f.present == nil {
		f.present = map[string]bool{}
	}
	f.present[naturalKey(doc.Meta.AuthenticSource, doc.Meta.Scope, doc.Meta.DocumentID)] = true
	f.saved = append(f.saved, doc)
	return nil
}

func (f *fakeDatastore) Count(context.Context) (int64, error) { return 0, nil }
func (f *fakeDatastore) SaveMany(context.Context, []*model.CompleteDocument) error {
	return nil
}
func (f *fakeDatastore) AddIdentity(context.Context, *db.AddIdentityQuery) error    { return nil }
func (f *fakeDatastore) DeleteIdentity(context.Context, *db.DeleteIdentityQuery) error {
	return nil
}
func (f *fakeDatastore) Delete(context.Context, *model.MetaData) error { return nil }
func (f *fakeDatastore) Get(context.Context, *model.MetaData) (*model.Document, error) {
	return nil, nil
}
func (f *fakeDatastore) GetByIdentity(context.Context, string, string) (map[string]*model.CompleteDocument, error) {
	return nil, nil
}
func (f *fakeDatastore) List(context.Context, *db.ListQuery) ([]*model.DocumentList, error) {
	return nil, nil
}
func (f *fakeDatastore) Replace(_ context.Context, doc *model.CompleteDocument) error {
	f.replaced = append(f.replaced, doc)
	return nil
}
func (f *fakeDatastore) DeleteByKey(context.Context, string, string, string) error {
	return nil
}
func (f *fakeDatastore) Search(context.Context, *db.SearchDocumentsQuery) ([]*model.CompleteDocument, error) {
	return nil, nil
}
func (f *fakeDatastore) ListAuthenticSources(context.Context) ([]string, error) {
	return nil, nil
}

func writeDocsFile(t *testing.T, docs map[string]*model.CompleteDocument) string {
	t.Helper()
	b, err := json.Marshal(docs)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "microcredential.json")
	require.NoError(t, os.WriteFile(path, b, 0o600))
	return path
}

func doc(id string) *model.CompleteDocument {
	return &model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: "Ladok",
			Scope:           "microcredential",
			DocumentID:      "document_id_" + id,
		},
	}
}

func TestImportDocuments_SavesMissing(t *testing.T) {
	path := writeDocsFile(t, map[string]*model.CompleteDocument{"100": doc("100"), "101": doc("101")})
	store := &fakeDatastore{present: map[string]bool{}}

	err := importDocuments(context.Background(), path, "microcredential", nil, false, store, logger.NewSimple("test"))
	require.NoError(t, err)
	assert.Len(t, store.saved, 2)
}

func TestImportDocuments_SkipsExisting(t *testing.T) {
	path := writeDocsFile(t, map[string]*model.CompleteDocument{"100": doc("100"), "101": doc("101")})
	store := &fakeDatastore{present: map[string]bool{
		naturalKey("Ladok", "microcredential", "document_id_100"): true,
	}}

	err := importDocuments(context.Background(), path, "microcredential", nil, false, store, logger.NewSimple("test"))
	require.NoError(t, err)
	require.Len(t, store.saved, 1)
	assert.Equal(t, "document_id_101", store.saved[0].Meta.DocumentID)
}

func TestImportDocuments_ReplaceExistingReplaces(t *testing.T) {
	path := writeDocsFile(t, map[string]*model.CompleteDocument{"100": doc("100"), "101": doc("101")})
	store := &fakeDatastore{present: map[string]bool{
		naturalKey("Ladok", "microcredential", "document_id_100"): true,
	}}

	err := importDocuments(context.Background(), path, "microcredential", nil, true, store, logger.NewSimple("test"))
	require.NoError(t, err)
	// The present document is replaced, the missing one is saved.
	require.Len(t, store.replaced, 1)
	assert.Equal(t, "document_id_100", store.replaced[0].Meta.DocumentID)
	require.Len(t, store.saved, 1)
	assert.Equal(t, "document_id_101", store.saved[0].Meta.DocumentID)
}

func TestImportDocuments_LookupErrorPropagates(t *testing.T) {
	path := writeDocsFile(t, map[string]*model.CompleteDocument{"100": doc("100")})
	boom := errors.New("datastore down")
	store := &fakeDatastore{getByKey: func(string, string, string) (*model.CompleteDocument, error) {
		return nil, boom
	}}

	err := importDocuments(context.Background(), path, "microcredential", nil, false, store, logger.NewSimple("test"))
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

func TestImportDocuments_SaveRaceSkips(t *testing.T) {
	path := writeDocsFile(t, map[string]*model.CompleteDocument{"100": doc("100")})
	present := map[string]bool{}
	store := &fakeDatastore{
		present: present,
		// A concurrent importer wins the race: Save fails on the unique key
		// and the document now exists, so the follow-up presence check sees it.
		save: func(d *model.CompleteDocument) error {
			present[naturalKey(d.Meta.AuthenticSource, d.Meta.Scope, d.Meta.DocumentID)] = true
			return errors.New("duplicate key")
		},
	}

	err := importDocuments(context.Background(), path, "microcredential", nil, false, store, logger.NewSimple("test"))
	require.NoError(t, err)
	assert.Empty(t, store.saved)
}

func TestImportDocuments_SaveErrorPropagates(t *testing.T) {
	path := writeDocsFile(t, map[string]*model.CompleteDocument{"100": doc("100")})
	boom := errors.New("disk full")
	store := &fakeDatastore{
		present: map[string]bool{},
		// Save fails and the document is still absent, so the error is real.
		save: func(*model.CompleteDocument) error { return boom },
	}

	err := importDocuments(context.Background(), path, "microcredential", nil, false, store, logger.NewSimple("test"))
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}