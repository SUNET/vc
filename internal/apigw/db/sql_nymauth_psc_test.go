package db

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/testsupport/sqltest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pscDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// testNymAuthPSCStoreContract is the whole rule this store exists for,
// written once and run against every backend: one holder-supplied
// commitment per subject, changed only by an operator-approved reset
// that leaves a trail.
func testNymAuthPSCStoreContract(t *testing.T, store NymAuthPSCStore) {
	t.Helper()
	ctx := t.Context()

	subject := pscDigest("subject-one")
	first := pscDigest("private-seed-one")
	second := pscDigest("private-seed-two")
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

	t.Run("an unknown subject has no record", func(t *testing.T) {
		got, err := store.Get(ctx, pscDigest("nobody"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("the first commitment is recorded", func(t *testing.T) {
		require.NoError(t, store.Accept(ctx, subject, first, now))

		got, err := store.Get(ctx, subject)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, first, got.PSC)
		assert.Equal(t, subject, got.SubjectKey)
		assert.WithinDuration(t, now, got.AcceptedAt, time.Second)
	})

	t.Run("the same commitment again is not a conflict", func(t *testing.T) {
		// Re-issuance, batch issuance and a retried request all reach
		// this legitimately.
		require.NoError(t, store.Accept(ctx, subject, first, now.Add(time.Hour)))

		got, err := store.Get(ctx, subject)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, first, got.PSC)
		assert.WithinDuration(t, now, got.AcceptedAt, time.Second,
			"accepted_at records the FIRST acceptance and must not move")
	})

	t.Run("a different commitment is refused, and changes nothing", func(t *testing.T) {
		err := store.Accept(ctx, subject, second, now)
		assert.ErrorIs(t, err, ErrPSCConflict)

		got, err := store.Get(ctx, subject)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, first, got.PSC, "the refused value must not have overwritten the record")
	})

	t.Run("a reset of a subject with no record is refused", func(t *testing.T) {
		err := store.Reset(ctx, pscDigest("nobody"), "operator-1", "evidence-x", now)
		assert.ErrorIs(t, err, ErrPSCNoRecord)
	})

	t.Run("a reset needs an approver and evidence", func(t *testing.T) {
		assert.Error(t, store.Reset(ctx, subject, "", "evidence-1", now))
		assert.Error(t, store.Reset(ctx, subject, "operator-1", "", now))
	})

	t.Run("a reset clears the record and leaves a trail", func(t *testing.T) {
		require.NoError(t, store.Reset(ctx, subject, "operator-1", "evidence-1", now.Add(2*time.Hour)))

		got, err := store.Get(ctx, subject)
		require.NoError(t, err)
		assert.Nil(t, got, "the record is gone, so the next commitment starts a new one")

		trail, err := store.Resets(ctx, subject)
		require.NoError(t, err)
		require.Len(t, trail, 1)
		assert.Equal(t, "operator-1", trail[0].ApprovedBy)
		assert.Equal(t, "evidence-1", trail[0].EvidenceRef)
		assert.Equal(t, ResetOf(first), trail[0].ResetOf)
		assert.NotEqual(t, first, trail[0].ResetOf,
			"the trail carries a HASH of the previous commitment, never a working key to the old pseudonyms")
	})

	t.Run("after a reset a different commitment is accepted", func(t *testing.T) {
		require.NoError(t, store.Accept(ctx, subject, second, now.Add(3*time.Hour)))

		got, err := store.Get(ctx, subject)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, second, got.PSC)
	})

	t.Run("replaying a reset changes nothing", func(t *testing.T) {
		// This is the whole point of keying idempotency on the
		// evidence: by now the subject has legitimately re-established
		// a record, and a replayed request must not discard it.
		require.NoError(t, store.Reset(ctx, subject, "operator-1", "evidence-1", now.Add(4*time.Hour)))

		got, err := store.Get(ctx, subject)
		require.NoError(t, err)
		require.NotNil(t, got, "the re-established record must survive a replayed reset")
		assert.Equal(t, second, got.PSC)

		trail, err := store.Resets(ctx, subject)
		require.NoError(t, err)
		assert.Len(t, trail, 1, "one piece of evidence resets a subject once")
	})

	t.Run("a second reset appends to the trail, oldest first", func(t *testing.T) {
		require.NoError(t, store.Reset(ctx, subject, "operator-2", "evidence-2", now.Add(5*time.Hour)))

		trail, err := store.Resets(ctx, subject)
		require.NoError(t, err)
		require.Len(t, trail, 2)
		assert.Equal(t, "evidence-1", trail[0].EvidenceRef)
		assert.Equal(t, "evidence-2", trail[1].EvidenceRef)
		assert.Equal(t, ResetOf(second), trail[1].ResetOf)
	})

	t.Run("erasure removes the record and the trail together", func(t *testing.T) {
		require.NoError(t, store.Accept(ctx, subject, first, now.Add(6*time.Hour)))
		require.NoError(t, store.Erase(ctx, subject))

		got, err := store.Get(ctx, subject)
		require.NoError(t, err)
		assert.Nil(t, got)

		trail, err := store.Resets(ctx, subject)
		require.NoError(t, err)
		assert.Empty(t, trail, "a trail outliving its record is a retained identifier with no purpose")
	})

	t.Run("malformed arguments are refused before they reach the table", func(t *testing.T) {
		assert.ErrorContains(t, store.Accept(ctx, "not-hex", first, now), "not hex")
		assert.ErrorContains(t, store.Accept(ctx, subject, "abcd", now), "not 32")
		assert.ErrorContains(t, store.Accept(ctx, strings.Repeat("aa", 31), first, now), "not 32")
		assert.ErrorContains(t, store.Reset(ctx, "not-hex", "operator-1", "evidence-9", now), "not hex")
	})
}

func TestSQLNymAuthPSCColl_Postgres(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartPostgres(t)
	defer cleanup()

	testNymAuthPSCStoreContract(t, NewSQLNymAuthPSCColl(newTestService(t), sqlDB, dialect))
}

func TestSQLNymAuthPSCColl_MariaDB(t *testing.T) {
	sqlDB, dialect, cleanup := sqltest.StartMariaDB(t)
	defer cleanup()

	testNymAuthPSCStoreContract(t, NewSQLNymAuthPSCColl(newTestService(t), sqlDB, dialect))
}
