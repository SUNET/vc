package apiv2

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFullLifecycle tests the complete workflow: create mapping → upload doc → resolve → get → delete.
func TestFullLifecycle(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Step 1: Create identity mapping
	mappingReply, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "EHIC_DB",
		Identifier:      "id-lifecycle-001",
		Attributes:      map[string]string{"ssn": "199001011234", "nationality": "SE"},
	})
	require.NoError(t, err)
	assert.Equal(t, "id-lifecycle-001", mappingReply.Identifier)

	// Step 2: Upload document linked to the identifier
	validFrom := int64(1700000000)
	validTo := int64(1800000000)
	uploadReply, err := client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource:     "EHIC_DB",
			Scope:               "ehic",
			DocumentID:          "doc-lifecycle-001",
			CredentialValidFrom: &validFrom,
			CredentialValidTo:   &validTo,
		},
		Identities:   []string{"id-lifecycle-001"},
		DocumentData: map[string]any{"card_number": "SE-EHIC-12345", "institution": "Försäkringskassan"},
	})
	require.NoError(t, err)
	assert.Equal(t, "doc-lifecycle-001", uploadReply.DocumentID)

	// Step 3: Resolve identity → get documents (single-step)
	resolveReply, err := client.ResolveDocuments(ctx, &ResolveDocumentsRequest{
		AuthenticSource: "EHIC_DB",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "199001011234", "nationality": "SE"},
	})
	require.NoError(t, err)
	assert.Equal(t, "id-lifecycle-001", resolveReply.Identifier)
	require.Len(t, resolveReply.Documents, 1)
	assert.Equal(t, "SE-EHIC-12345", resolveReply.Documents[0].DocumentData["card_number"])

	// Step 4: Get document directly by key
	getReply, err := client.GetDocument(ctx, &GetDocumentRequest{
		AuthenticSource: "EHIC_DB",
		Scope:           "ehic",
		DocumentID:      "doc-lifecycle-001",
	})
	require.NoError(t, err)
	assert.Equal(t, "Försäkringskassan", getReply.Document.DocumentData["institution"])
	assert.Equal(t, validFrom, *getReply.Document.Meta.CredentialValidFrom)
	assert.Equal(t, validTo, *getReply.Document.Meta.CredentialValidTo)

	// Step 5: Update identity mapping attributes
	err = client.UpdateIdentityMapping(ctx, &UpdateIdentityMappingRequest{
		AuthenticSource: "EHIC_DB",
		Identifier:      "id-lifecycle-001",
		Attributes:      map[string]string{"ssn": "199001011234", "nationality": "SE", "email": "erik@example.com"},
	})
	require.NoError(t, err)

	// Step 6: Verify resolution still works with new attributes
	resolveReply2, err := client.ResolveDocuments(ctx, &ResolveDocumentsRequest{
		AuthenticSource: "EHIC_DB",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "199001011234", "nationality": "SE", "email": "erik@example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "id-lifecycle-001", resolveReply2.Identifier)

	// Step 7: Delete document
	err = client.DeleteDocument(ctx, &DeleteDocumentRequest{
		AuthenticSource: "EHIC_DB",
		Scope:           "ehic",
		DocumentID:      "doc-lifecycle-001",
	})
	require.NoError(t, err)

	// Step 8: Verify document is gone
	_, err = client.GetDocument(ctx, &GetDocumentRequest{
		AuthenticSource: "EHIC_DB",
		Scope:           "ehic",
		DocumentID:      "doc-lifecycle-001",
	})
	assert.Error(t, err)

	// Step 9: Delete identity mapping
	err = client.DeleteIdentityMapping(ctx, &DeleteIdentityMappingRequest{
		AuthenticSource: "EHIC_DB",
		Identifier:      "id-lifecycle-001",
	})
	require.NoError(t, err)

	// Step 10: Verify mapping is gone
	_, err = client.ResolveDocuments(ctx, &ResolveDocumentsRequest{
		AuthenticSource: "EHIC_DB",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "199001011234", "nationality": "SE", "email": "erik@example.com"},
	})
	assert.Error(t, err)
}

// TestMultipleDocumentsPerIdentity verifies that one identity can have multiple documents.
func TestMultipleDocumentsPerIdentity(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Create mapping
	_, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "AS1",
		Identifier:      "multi-doc-person",
		Attributes:      map[string]string{"ssn": "010101-0101"},
	})
	require.NoError(t, err)

	// Upload multiple documents for different scopes
	scopes := []string{"ehic", "pda1", "diploma"}
	for _, scope := range scopes {
		_, err := client.UploadDocument(ctx, &UploadDocumentRequest{
			Meta: &model.V2MetaData{
				AuthenticSource: "AS1",
				Scope:           scope,
				DocumentID:      "doc-" + scope,
			},
			Identities:   []string{"multi-doc-person"},
			DocumentData: map[string]any{"scope": scope},
		})
		require.NoError(t, err)
	}

	// List all documents
	reply, err := client.ListDocuments(ctx, &ListDocumentsRequest{
		AuthenticSource: "AS1",
		Identifier:      "multi-doc-person",
	})
	require.NoError(t, err)
	assert.Len(t, reply.Documents, 3)

	// List by specific scope
	reply, err = client.ListDocuments(ctx, &ListDocumentsRequest{
		AuthenticSource: "AS1",
		Identifier:      "multi-doc-person",
		Scope:           "pda1",
	})
	require.NoError(t, err)
	assert.Len(t, reply.Documents, 1)
	assert.Equal(t, "pda1", reply.Documents[0].Meta.Scope)
}

// TestMultipleIdentitiesPerDocument verifies that one document can be linked to multiple identifiers.
func TestMultipleIdentitiesPerDocument(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Create two identity mappings
	_, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "AS1",
		Identifier:      "person-A",
		Attributes:      map[string]string{"ssn": "111111-1111"},
	})
	require.NoError(t, err)

	_, err = client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "AS1",
		Identifier:      "person-B",
		Attributes:      map[string]string{"email": "b@example.com"},
	})
	require.NoError(t, err)

	// Upload a document linked to both
	_, err = client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "AS1",
			Scope:           "shared",
			DocumentID:      "shared-doc",
		},
		Identities:   []string{"person-A", "person-B"},
		DocumentData: map[string]any{"shared": true},
	})
	require.NoError(t, err)

	// Both identifiers should find the document
	for _, identifier := range []string{"person-A", "person-B"} {
		reply, err := client.ListDocuments(ctx, &ListDocumentsRequest{
			AuthenticSource: "AS1",
			Identifier:      identifier,
			Scope:           "shared",
		})
		require.NoError(t, err, "identifier: %s", identifier)
		assert.Len(t, reply.Documents, 1, "identifier: %s", identifier)
		assert.Equal(t, "shared-doc", reply.Documents[0].Meta.DocumentID)
	}
}

// TestAuthenticSourceIsolation ensures different authentic sources don't leak data.
func TestAuthenticSourceIsolation(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Create same identifier in two authentic sources
	_, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "SOURCE_A",
		Identifier:      "person-001",
		Attributes:      map[string]string{"ssn": "010101-0101"},
	})
	require.NoError(t, err)

	_, err = client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "SOURCE_B",
		Identifier:      "person-001",
		Attributes:      map[string]string{"ssn": "020202-0202"},
	})
	require.NoError(t, err)

	// Upload documents in each source
	_, err = client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "SOURCE_A",
			Scope:           "ehic",
			DocumentID:      "doc-a",
		},
		Identities:   []string{"person-001"},
		DocumentData: map[string]any{"source": "A"},
	})
	require.NoError(t, err)

	_, err = client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "SOURCE_B",
			Scope:           "ehic",
			DocumentID:      "doc-b",
		},
		Identities:   []string{"person-001"},
		DocumentData: map[string]any{"source": "B"},
	})
	require.NoError(t, err)

	// Resolve from SOURCE_A should only see SOURCE_A's document
	reply, err := client.ResolveDocuments(ctx, &ResolveDocumentsRequest{
		AuthenticSource: "SOURCE_A",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "010101-0101"},
	})
	require.NoError(t, err)
	require.Len(t, reply.Documents, 1)
	assert.Equal(t, "A", reply.Documents[0].DocumentData["source"])

	// Cross-source resolution should fail
	_, err = client.ResolveDocuments(ctx, &ResolveDocumentsRequest{
		AuthenticSource: "SOURCE_A",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "020202-0202"}, // SOURCE_B's SSN
	})
	assert.Error(t, err)
}

// TestCredentialIssuanceFlow simulates the credential issuance integration path.
func TestCredentialIssuanceFlow(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	// Setup: Create identity mapping with name-based attributes (as would come from v1 Identity)
	_, err := client.CreateIdentityMapping(ctx, &CreateIdentityMappingRequest{
		AuthenticSource: "SUNET",
		Identifier:      "credential-subject-001",
		Attributes:      map[string]string{"family_name": "Johansson", "given_name": "Erik", "birth_date": "1990-01-01"},
	})
	require.NoError(t, err)

	// Upload a credential document
	_, err = client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			DocumentID:      "cred-doc-001",
		},
		Identities: []string{"credential-subject-001"},
		DocumentData: map[string]any{
			"card_number":       "SE-EHIC-001",
			"institution_id":    "SE:FK",
			"institution_name":  "Försäkringskassan",
			"valid_from":        "2024-01-01",
			"valid_to":          "2025-01-01",
		},
	})
	require.NoError(t, err)

	// Simulate issuance: use IdentityToAttributes to convert v1 Identity to v2 attributes
	identity := &model.Identity{
		FamilyName: "Johansson",
		GivenName:  "Erik",
		BirthDate:  "1990-01-01",
	}
	attrs := IdentityToAttributes(identity)

	// Use GetDocumentForCredential (the issuance path)
	doc, err := client.GetDocumentForCredential(ctx, "SUNET", "ehic", attrs)
	require.NoError(t, err)
	assert.Equal(t, "cred-doc-001", doc.Meta.DocumentID)
	assert.Equal(t, "SE-EHIC-001", doc.DocumentData["card_number"])
	assert.Equal(t, "SUNET", doc.Meta.AuthenticSource)
	assert.Equal(t, "ehic", doc.Meta.Scope)
}

// TestEmptyResults verifies correct behavior when no data exists.
func TestEmptyResults(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	t.Run("list documents for non-existent identifier", func(t *testing.T) {
		reply, err := client.ListDocuments(ctx, &ListDocumentsRequest{
			AuthenticSource: "SUNET",
			Identifier:      "non-existent",
		})
		require.NoError(t, err)
		assert.Len(t, reply.Documents, 0)
	})

	t.Run("resolve with no mappings", func(t *testing.T) {
		_, err := client.ResolveDocuments(ctx, &ResolveDocumentsRequest{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			Attributes:      map[string]string{"ssn": "no-match"},
		})
		assert.Error(t, err)
	})

	t.Run("get non-existent document", func(t *testing.T) {
		_, err := client.GetDocument(ctx, &GetDocumentRequest{
			AuthenticSource: "SUNET",
			Scope:           "ehic",
			DocumentID:      "does-not-exist",
		})
		assert.Error(t, err)
	})
}

// TestDocumentDataIntegrity ensures document_data is stored and retrieved without modification.
func TestDocumentDataIntegrity(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	complexData := map[string]any{
		"string_field": "hello",
		"int_field":    float64(42), // JSON numbers are float64
		"bool_field":   true,
		"null_field":   nil,
		"nested": map[string]any{
			"inner_string": "world",
			"inner_array":  []any{"a", "b", "c"},
		},
		"array_field": []any{float64(1), float64(2), float64(3)},
	}

	_, err := client.UploadDocument(ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource: "AS1",
			Scope:           "test",
			DocumentID:      "complex-doc",
		},
		Identities:   []string{"id-1"},
		DocumentData: complexData,
	})
	require.NoError(t, err)

	reply, err := client.GetDocument(ctx, &GetDocumentRequest{
		AuthenticSource: "AS1",
		Scope:           "test",
		DocumentID:      "complex-doc",
	})
	require.NoError(t, err)

	// Verify all fields preserved
	assert.Equal(t, "hello", reply.Document.DocumentData["string_field"])
	assert.Equal(t, float64(42), reply.Document.DocumentData["int_field"])
	assert.Equal(t, true, reply.Document.DocumentData["bool_field"])
	assert.Nil(t, reply.Document.DocumentData["null_field"])

	nested, ok := reply.Document.DocumentData["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "world", nested["inner_string"])
}

// TestOptionalMetadataFields verifies that optional metadata fields work correctly.
func TestOptionalMetadataFields(t *testing.T) {
	store := newMockStore()
	client := newTestClient(store)
	ctx := context.Background()

	t.Run("document without validity dates", func(t *testing.T) {
		_, err := client.UploadDocument(ctx, &UploadDocumentRequest{
			Meta: &model.V2MetaData{
				AuthenticSource: "AS1",
				Scope:           "test",
				DocumentID:      "no-dates",
			},
			Identities:   []string{"id-1"},
			DocumentData: map[string]any{"data": "value"},
		})
		require.NoError(t, err)

		reply, err := client.GetDocument(ctx, &GetDocumentRequest{
			AuthenticSource: "AS1",
			Scope:           "test",
			DocumentID:      "no-dates",
		})
		require.NoError(t, err)
		assert.Nil(t, reply.Document.Meta.CredentialValidFrom)
		assert.Nil(t, reply.Document.Meta.CredentialValidTo)
		assert.Nil(t, reply.Document.Meta.Revocation)
	})

	t.Run("document with revocation info", func(t *testing.T) {
		revocation := &model.Revocation{
			Revoked: true,
		}
		_, err := client.UploadDocument(ctx, &UploadDocumentRequest{
			Meta: &model.V2MetaData{
				AuthenticSource: "AS1",
				Scope:           "test",
				DocumentID:      "revoked-doc",
				Revocation:      revocation,
			},
			Identities:   []string{"id-1"},
			DocumentData: map[string]any{"data": "revoked"},
		})
		require.NoError(t, err)

		reply, err := client.GetDocument(ctx, &GetDocumentRequest{
			AuthenticSource: "AS1",
			Scope:           "test",
			DocumentID:      "revoked-doc",
		})
		require.NoError(t, err)
		require.NotNil(t, reply.Document.Meta.Revocation)
		assert.True(t, reply.Document.Meta.Revocation.Revoked)
	})
}
