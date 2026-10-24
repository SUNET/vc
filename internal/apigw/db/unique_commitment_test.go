package db

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/testsupport/sqltest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testUniqueCommitmentStoreContract: one commitment per key, whichever
// writer reaches the database first; a reset needs a commitment on record,
// and its evidence reference resets one commitment.
func testUniqueCommitmentStoreContract(t *testing.T, store UniqueCommitmentStore) {
	ctx := t.Context()
	now := time.Now()
	key := UniqueCommitmentKey{Scope: "nym_auth", Path: []string{"eu.europa.ec.eudi.nym_auth.1", "psc"}, KeyHash: []byte("key of a person")}
	first, second := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)

	stored, err := store.Accept(ctx, key, first, now)
	require.NoError(t, err)
	assert.Equal(t, first, stored)
	stored, err = store.Accept(ctx, key, second, now)
	require.NoError(t, err)
	assert.Equal(t, first, stored, "the first commitment stays")

	// Concurrent writers on a fresh key all read back one stored commitment.
	racing := UniqueCommitmentKey{Scope: key.Scope, Path: key.Path, KeyHash: []byte("key of another person")}
	results := make([][]byte, 8)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stored, err := store.Accept(ctx, racing, bytes.Repeat([]byte{byte(10 + i)}, 32), now)
			assert.NoError(t, err)
			results[i] = stored
		}(i)
	}
	wg.Wait()
	for _, r := range results {
		assert.Equal(t, results[0], r, "every writer reads back the same commitment")
	}

	approval := UniqueCommitmentReset{ApprovedBy: "operator", EvidenceRef: "case-1", At: now}
	require.NoError(t, store.Reset(ctx, key, approval))
	stored, err = store.Accept(ctx, key, second, now)
	require.NoError(t, err)
	assert.Equal(t, second, stored, "after a reset the next commitment is stored")

	assert.ErrorIs(t, store.Reset(ctx, UniqueCommitmentKey{Scope: key.Scope, Path: key.Path, KeyHash: []byte("key of nobody on record")}, approval),
		ErrNoDocuments, "a reset needs a commitment on record")
	assert.ErrorIs(t, store.Reset(ctx, key, approval), ErrResetEvidenceUsed, "an evidence reference resets one commitment")
	stored, err = store.Accept(ctx, key, first, now)
	require.NoError(t, err)
	assert.Equal(t, second, stored, "a refused reset leaves the commitment on record")
}

func TestUniqueCommitmentColl_Mongo(t *testing.T) {
	client, cleanup := startMongoContainerForTest(t)
	defer cleanup()

	store, err := NewUniqueCommitmentColl(t.Context(), newTestServiceWithMongo(t, client))
	require.NoError(t, err)
	testUniqueCommitmentStoreContract(t, store)
}

func TestSQLUniqueCommitmentColl_Postgres(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartPostgres(t)
	defer cleanup()

	testUniqueCommitmentStoreContract(t, NewSQLUniqueCommitmentColl(newTestService(t), sqlDB, dialect))
}

func TestSQLUniqueCommitmentColl_MariaDB(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartMariaDB(t)
	defer cleanup()

	testUniqueCommitmentStoreContract(t, NewSQLUniqueCommitmentColl(newTestService(t), sqlDB, dialect))
}
