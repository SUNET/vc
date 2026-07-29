package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/helpers"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newIdentityMappingTestClient(t *testing.T) (*Client, *memoryIdentityMappingStore) {
	t.Helper()
	client, _, identityStore := newDatastoreTestClient(t)
	return client, identityStore
}

// --- IdentityMappingCreate ---

func TestIdentityMappingCreate(t *testing.T) {
	t.Run("with provided person ID", func(t *testing.T) {
		client, identityStore := newIdentityMappingTestClient(t)

		reply, err := client.IdentityMappingCreate(t.Context(), &IdentityMappingCreateRequest{
			AuthenticSource:         "SUNET",
			AuthenticSourcePersonID: "custom-id-001",
			Attributes:              map[string]string{"ssn": "199001011234"},
		})
		require.NoError(t, err)
		assert.Equal(t, "custom-id-001", reply.AuthenticSourcePersonID)

		// Verify stored correctly
		identityStore.mu.RLock()
		m := identityStore.mappings[mappingKey("SUNET", "custom-id-001")]
		identityStore.mu.RUnlock()
		require.NotNil(t, m)
		assert.Equal(t, "199001011234", m.Attributes["ssn"])
	})

	t.Run("auto-generates UUIDv7 when ID is empty", func(t *testing.T) {
		client, _ := newIdentityMappingTestClient(t)

		reply, err := client.IdentityMappingCreate(t.Context(), &IdentityMappingCreateRequest{
			AuthenticSource: "SUNET",
			Attributes:      map[string]string{"given_name": "Erik"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, reply.AuthenticSourcePersonID)

		// Verify it's a valid UUID
		_, err = uuid.Parse(reply.AuthenticSourcePersonID)
		require.NoError(t, err)
	})

	t.Run("duplicate mapping returns error", func(t *testing.T) {
		client, identityStore := newIdentityMappingTestClient(t)
		seedMapping(t, identityStore, "SUNET", "dup-person", map[string]string{"x": "1"})

		_, err := client.IdentityMappingCreate(t.Context(), &IdentityMappingCreateRequest{
			AuthenticSource:         "SUNET",
			AuthenticSourcePersonID: "dup-person",
			Attributes:              map[string]string{"x": "2"},
		})
		assert.Error(t, err)
	})

	t.Run("nil attributes", func(t *testing.T) {
		client, _ := newIdentityMappingTestClient(t)

		reply, err := client.IdentityMappingCreate(t.Context(), &IdentityMappingCreateRequest{
			AuthenticSource:         "SUNET",
			AuthenticSourcePersonID: "no-attrs",
		})
		require.NoError(t, err)
		assert.Equal(t, "no-attrs", reply.AuthenticSourcePersonID)
	})
}

// --- IdentityMappingResolve ---

func TestIdentityMappingResolve(t *testing.T) {
	t.Run("resolves matching attributes", func(t *testing.T) {
		client, identityStore := newIdentityMappingTestClient(t)
		seedMapping(t, identityStore, "SUNET", "person-resolve", map[string]string{
			"family_name": "Johansson",
			"given_name":  "Erik",
		})

		reply, err := client.IdentityMappingResolve(t.Context(), &IdentityMappingResolveRequest{
			AuthenticSource: "SUNET",
			Attributes:      map[string]string{"family_name": "Johansson", "given_name": "Erik"},
		})
		require.NoError(t, err)
		assert.Equal(t, "person-resolve", reply.AuthenticSourcePersonID)
	})

	t.Run("no match returns error", func(t *testing.T) {
		client, _ := newIdentityMappingTestClient(t)

		_, err := client.IdentityMappingResolve(t.Context(), &IdentityMappingResolveRequest{
			AuthenticSource: "SUNET",
			Attributes:      map[string]string{"family_name": "Unknown"},
		})
		assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
	})

	t.Run("wrong authentic source returns error", func(t *testing.T) {
		client, identityStore := newIdentityMappingTestClient(t)
		seedMapping(t, identityStore, "SUNET", "person-src", map[string]string{"ssn": "111"})

		_, err := client.IdentityMappingResolve(t.Context(), &IdentityMappingResolveRequest{
			AuthenticSource: "OTHER",
			Attributes:      map[string]string{"ssn": "111"},
		})
		assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
	})
}

// --- IdentityMappingUpdate ---

func TestIdentityMappingUpdate(t *testing.T) {
	t.Run("updates attributes", func(t *testing.T) {
		client, identityStore := newIdentityMappingTestClient(t)
		seedMapping(t, identityStore, "SUNET", "person-upd", map[string]string{"ssn": "old"})

		err := client.IdentityMappingUpdate(t.Context(), &IdentityMappingUpdateRequest{
			AuthenticSource:         "SUNET",
			AuthenticSourcePersonID: "person-upd",
			Attributes:              map[string]string{"ssn": "new", "email": "test@example.com"},
		})
		require.NoError(t, err)

		// Verify updated
		identityStore.mu.RLock()
		m := identityStore.mappings[mappingKey("SUNET", "person-upd")]
		identityStore.mu.RUnlock()
		assert.Equal(t, "new", m.Attributes["ssn"])
		assert.Equal(t, "test@example.com", m.Attributes["email"])
	})

	t.Run("non-existent mapping returns error", func(t *testing.T) {
		client, _ := newIdentityMappingTestClient(t)

		err := client.IdentityMappingUpdate(t.Context(), &IdentityMappingUpdateRequest{
			AuthenticSource:         "SUNET",
			AuthenticSourcePersonID: "no-such-person",
			Attributes:              map[string]string{"x": "1"},
		})
		assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
	})
}

// --- IdentityMappingDelete ---

func TestIdentityMappingDelete(t *testing.T) {
	t.Run("deletes existing mapping", func(t *testing.T) {
		client, identityStore := newIdentityMappingTestClient(t)
		seedMapping(t, identityStore, "SUNET", "person-del", map[string]string{"ssn": "999"})

		err := client.IdentityMappingDelete(t.Context(), &IdentityMappingDeleteRequest{
			AuthenticSource:         "SUNET",
			AuthenticSourcePersonID: "person-del",
		})
		require.NoError(t, err)

		// Verify it's gone
		_, err = client.IdentityMappingResolve(t.Context(), &IdentityMappingResolveRequest{
			AuthenticSource: "SUNET",
			Attributes:      map[string]string{"ssn": "999"},
		})
		assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
	})

	t.Run("non-existent mapping returns error", func(t *testing.T) {
		client, _ := newIdentityMappingTestClient(t)

		err := client.IdentityMappingDelete(t.Context(), &IdentityMappingDeleteRequest{
			AuthenticSource:         "SUNET",
			AuthenticSourcePersonID: "no-such",
		})
		assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
	})
}

// --- Identity mapping lifecycle ---

func TestIdentityMappingLifecycle(t *testing.T) {
	client, _ := newIdentityMappingTestClient(t)

	// 1. Create with auto-generated ID
	createReply, err := client.IdentityMappingCreate(t.Context(), &IdentityMappingCreateRequest{
		AuthenticSource: "SUNET",
		Attributes:      map[string]string{"family_name": "Svensson", "given_name": "Anna"},
	})
	require.NoError(t, err)
	personID := createReply.AuthenticSourcePersonID

	// 2. Resolve by attributes
	resolveReply, err := client.IdentityMappingResolve(t.Context(), &IdentityMappingResolveRequest{
		AuthenticSource: "SUNET",
		Attributes:      map[string]string{"family_name": "Svensson", "given_name": "Anna"},
	})
	require.NoError(t, err)
	assert.Equal(t, personID, resolveReply.AuthenticSourcePersonID)

	// 3. Update attributes
	err = client.IdentityMappingUpdate(t.Context(), &IdentityMappingUpdateRequest{
		AuthenticSource:         "SUNET",
		AuthenticSourcePersonID: personID,
		Attributes:              map[string]string{"family_name": "Svensson", "given_name": "Anna", "email": "anna@example.se"},
	})
	require.NoError(t, err)

	// 4. Resolve still works with updated attributes
	resolveReply, err = client.IdentityMappingResolve(t.Context(), &IdentityMappingResolveRequest{
		AuthenticSource: "SUNET",
		Attributes:      map[string]string{"family_name": "Svensson", "given_name": "Anna", "email": "anna@example.se"},
	})
	require.NoError(t, err)
	assert.Equal(t, personID, resolveReply.AuthenticSourcePersonID)

	// 5. Delete
	err = client.IdentityMappingDelete(t.Context(), &IdentityMappingDeleteRequest{
		AuthenticSource:         "SUNET",
		AuthenticSourcePersonID: personID,
	})
	require.NoError(t, err)

	// 6. Resolve fails after deletion
	_, err = client.IdentityMappingResolve(t.Context(), &IdentityMappingResolveRequest{
		AuthenticSource: "SUNET",
		Attributes:      map[string]string{"family_name": "Svensson", "given_name": "Anna", "email": "anna@example.se"},
	})
	assert.ErrorIs(t, err, helpers.ErrNoIdentityFound)
}
