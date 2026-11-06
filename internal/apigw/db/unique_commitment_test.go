package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	require.NoError(t, store.backend.keepCommitments(ctx, []uniqueCommitmentRow{stored}))
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

	// Of two accepts that share a fresh row, the second runs while the first
	// stores its other commitment. The row outlasts them when either succeeds.
	held := keyOf("a held person")
	require.NoError(t, accept(UniqueCommitment{held, second}))
	for i, tc := range []struct{ firstFails, secondFails, stays bool }{
		{firstFails: true, secondFails: true},
		{firstFails: true, stays: true},
		{secondFails: true, stays: true},
	} {
		shared := keyOf(fmt.Sprintf("a person two accepts share %d", i))
		other := func(call string, fails bool) UniqueCommitment {
			if fails {
				return UniqueCommitment{held, first}
			}
			return UniqueCommitment{keyOf(fmt.Sprintf("a person of the %s call %d", call, i)), first}
		}
		outcome := func(t *testing.T, fails bool, err error) {
			t.Helper()
			if fails {
				conflictAt(t, err, 1, "the other commitment conflicts")
				return
			}
			assert.NoError(t, err)
		}
		firstOther := other("first", tc.firstFails)
		during := func() {
			outcome(t, tc.secondFails, store.Accept(ctx, []UniqueCommitment{{shared, first}, other("second", tc.secondFails)}, now))
		}
		outcome(t, tc.firstFails, interleaved(t, store, firstOther.Key, during).Accept(ctx, []UniqueCommitment{{shared, first}, firstOther}, now))
		_, err = store.Find(ctx, shared)
		if tc.stays {
			assert.NoError(t, err, "the row stays when an accept succeeded: %+v", tc)
		} else {
			assert.ErrorIs(t, err, ErrNoDocuments, "two refused accepts leave nothing")
		}
	}

	// A keep that fails refuses the batch and leaves no row of it.
	batch := []UniqueCommitment{{keyOf("a person of a failed keep"), first}, {keyOf("another person of a failed keep"), first}}
	failedKeep := &UniqueCommitments{Service: store.Service, backend: failedKeepBackend{store.backend}}
	assert.ErrorIs(t, failedKeep.Accept(ctx, batch, now), errKeepFailed)
	for _, c := range batch {
		_, err = store.Find(ctx, c.Key)
		assert.ErrorIs(t, err, ErrNoDocuments, "the failed keep leaves nothing")
	}

	// An accept that succeeds holds each of its rows, also one a reset removed
	// while the accept stored another.
	removed, later := keyOf("a person reset during an accept"), keyOf("a person accepted after that reset")
	during := func() {
		require.NoError(t, store.Reset(ctx, removed, UniqueCommitmentReset{ApprovedBy: "operator", EvidenceRef: "case-during", At: now}))
	}
	require.NoError(t, interleaved(t, store, later, during).Accept(ctx, []UniqueCommitment{{removed, first}, {later, first}}, now))
	_, err = store.Find(ctx, removed)
	assert.NoError(t, err, "the accept stored the removed row again")
	conflictAt(t, accept(UniqueCommitment{removed, second}), 0, "the row stored again is kept")

	// A reset that lost to a reset under the same evidence reference leaves
	// the approval that reset relies on.
	contested := keyOf("a contested person")
	require.NoError(t, accept(UniqueCommitment{contested, first}))
	sameRef := UniqueCommitmentReset{ApprovedBy: "operator", EvidenceRef: "case-contested", At: now}
	during = func() { assert.NoError(t, store.Reset(ctx, contested, sameRef), "the reset that runs first succeeds") }
	assert.ErrorIs(t, interleaved(t, store, contested, during).Reset(ctx, contested, sameRef), ErrNoDocuments, "the other found the commitment gone")
	k, err := storedKeyOf(contested)
	require.NoError(t, err)
	_, err = store.backend.resetPrevious(ctx, k, sameRef.EvidenceRef)
	assert.NoError(t, err, "the approval of the reset that succeeded stays")
}

// errKeepFailed is the failure of failedKeepBackend.
var errKeepFailed = errors.New("the keep failed")

// failedKeepBackend fails each keep.
type failedKeepBackend struct{ uniqueCommitmentBackend }

func (failedKeepBackend) keepCommitments(context.Context, []uniqueCommitmentRow) error {
	return errKeepFailed
}

// interleavedBackend runs during once, before the first insert or delete of
// a commitment on key.
type interleavedBackend struct {
	uniqueCommitmentBackend
	key    storedKey
	during func()
}

func (b *interleavedBackend) interleave(key storedKey) {
	if during := b.during; during != nil && key == b.key {
		b.during = nil
		during()
	}
}

func (b *interleavedBackend) insertCommitment(ctx context.Context, row uniqueCommitmentRow) error {
	b.interleave(row.key())
	return b.uniqueCommitmentBackend.insertCommitment(ctx, row)
}

func (b *interleavedBackend) deleteCommitment(ctx context.Context, key storedKey, commitment string) (bool, error) {
	b.interleave(key)
	return b.uniqueCommitmentBackend.deleteCommitment(ctx, key, commitment)
}

// interleaved is store with during run at the first write to key.
func interleaved(t *testing.T, store *UniqueCommitments, key UniqueCommitmentKey, during func()) *UniqueCommitments {
	t.Helper()
	k, err := storedKeyOf(key)
	require.NoError(t, err)
	return &UniqueCommitments{Service: store.Service, backend: &interleavedBackend{uniqueCommitmentBackend: store.backend, key: k, during: during}}
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
