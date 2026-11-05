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
// writer reaches the database first; a refused accept leaves no commitment
// it stored, and a commitment another accept relies on stays; a reset
// needs a commitment on record, and its evidence reference resets one
// commitment.
func testUniqueCommitmentStoreContract(t *testing.T, store *UniqueCommitments) {
	ctx := t.Context()
	now := time.Now()
	keyOf := func(person string) UniqueCommitmentKey {
		return UniqueCommitmentKey{Scope: "nym_auth", Path: []string{"eu.europa.ec.eudi.nym_auth.1", "psc"}, KeyHash: []byte("key of " + person)}
	}
	key := keyOf("a person")
	first, second := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	accept := func(commitments ...UniqueCommitment) error { return store.Accept(ctx, commitments, now) }
	conflictAt := func(t *testing.T, err error, index int, msg string) {
		t.Helper()
		var conflict *UniqueCommitmentConflict
		require.ErrorAs(t, err, &conflict, msg)
		assert.Equal(t, index, conflict.Index, msg)
	}

	_, err := store.Find(ctx, key)
	assert.ErrorIs(t, err, ErrNoDocuments, "nothing is on record before a commitment is accepted")
	require.NoError(t, accept(UniqueCommitment{key, first}))
	record, err := store.Find(ctx, key)
	require.NoError(t, err)
	assert.WithinDuration(t, now, record.AcceptedAt, time.Second, "the record tells when it was accepted")
	conflictAt(t, accept(UniqueCommitment{key, second}), 0, "the first commitment stays")
	require.NoError(t, accept(UniqueCommitment{key, first}), "the same commitment is accepted again")

	// A refused accept removes the commitment it stored for another key,
	// and leaves the one another accept stored.
	fresh, shared := keyOf("a fresh person"), keyOf("a shared person")
	conflictAt(t, accept(UniqueCommitment{fresh, first}, UniqueCommitment{key, second}), 1, "the second key holds another commitment")
	_, err = store.Find(ctx, fresh)
	assert.ErrorIs(t, err, ErrNoDocuments, "the refused accept leaves nothing it stored")
	require.NoError(t, accept(UniqueCommitment{shared, first}))
	conflictAt(t, accept(UniqueCommitment{shared, first}, UniqueCommitment{key, second}), 1, "the second key holds another commitment")
	_, err = store.Find(ctx, shared)
	assert.NoError(t, err, "the refused accept leaves what another accept stored")

	// A row that an accept relied on stays when the accept that stored it
	// fails and releases what it stored.
	relied, err := storedKeyOf(keyOf("a relied-on person"))
	require.NoError(t, err)
	stored := uniqueCommitmentRow{Scope: relied.Scope, Path: relied.Path, KeyHash: relied.KeyHash, Commitment: "c", AcceptedAt: now.UTC(), ReleasableBy: "storer"}
	require.NoError(t, store.backend.insertCommitment(ctx, stored))
	require.NoError(t, store.backend.keepCommitment(ctx, relied, stored.Commitment))
	require.NoError(t, store.backend.releaseCommitment(ctx, relied, "storer"))
	_, err = store.backend.record(ctx, relied)
	require.NoError(t, err, "the kept row stays")
	unkept, err := storedKeyOf(keyOf("an unkept person"))
	require.NoError(t, err)
	stored.KeyHash = unkept.KeyHash
	require.NoError(t, store.backend.insertCommitment(ctx, stored))
	require.NoError(t, store.backend.releaseCommitment(ctx, unkept, "storer"))
	_, err = store.backend.record(ctx, unkept)
	assert.ErrorIs(t, err, ErrNoDocuments, "the storer releases a row nobody kept")

	// Of concurrent writers on a fresh key, one is accepted and the others
	// conflict with its commitment.
	racing := keyOf("another person")
	errs := make([]error, 8)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() { errs[i] = accept(UniqueCommitment{racing, bytes.Repeat([]byte{byte(10 + i)}, 32)}) })
	}
	wg.Wait()
	winners := 0
	for i, err := range errs {
		if err == nil {
			winners++
			require.NoError(t, accept(UniqueCommitment{racing, bytes.Repeat([]byte{byte(10 + i)}, 32)}), "the winner's commitment is on record")
			continue
		}
		conflictAt(t, err, 0, "every other writer conflicts")
	}
	assert.Equal(t, 1, winners, "one writer is accepted")

	approval := UniqueCommitmentReset{ApprovedBy: "operator", EvidenceRef: "case-1", At: now}
	require.NoError(t, store.Reset(ctx, key, approval))
	require.NoError(t, accept(UniqueCommitment{key, second}), "after a reset the next commitment is stored")

	assert.ErrorIs(t, store.Reset(ctx, keyOf("nobody on record"), approval), ErrNoDocuments, "a reset needs a commitment on record")
	assert.ErrorIs(t, store.Reset(ctx, key, approval), ErrResetEvidenceUsed, "an evidence reference resets one commitment")
	conflictAt(t, accept(UniqueCommitment{key, first}), 0, "a refused reset leaves the commitment on record")
	assert.NoError(t, store.Reset(ctx, key, UniqueCommitmentReset{ApprovedBy: "operator", EvidenceRef: "Case-1", At: now}),
		"evidence references that differ in case are distinct")
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
