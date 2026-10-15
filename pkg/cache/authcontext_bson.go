package cache

import (
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/openid4vp"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// MarshalBSON writes the authorization context, with the DCQL query
// written twice: once as the document every build can read, and once as
// JSON text, which is the only form that keeps the query's numbers.
//
// See DCQLQueryExact for why both. In short: BSON rounds a req param
// beyond int64 or float64 precision, a req param is an input to a proof,
// and replacing the stored representation outright would break a rolling
// upgrade in both directions.
func (a AuthorizationContext) MarshalBSON() ([]byte, error) {
	type plain AuthorizationContext // no methods, so no recursion
	document := plain(a)

	// Derived from DCQLQuery, so it is cleared before being rebuilt. A
	// context loaded from BSON carries the exact text in memory; a caller
	// that then CLEARS DCQLQuery and saves would otherwise leave the old
	// text in the replacement document, and the next read - which prefers
	// it - would restore the query that had just been removed.
	document.DCQLQueryExact = ""

	if a.DCQLQuery != nil {
		encoded, err := json.Marshal(a.DCQLQuery)
		if err != nil {
			return nil, fmt.Errorf("authorization context: encoding the dcql query: %w", err)
		}
		document.DCQLQueryExact = string(encoded)
	}

	stored, err := bson.Marshal(document)
	if err == nil {
		return stored, nil
	}
	if document.DCQLQuery == nil {
		return nil, err
	}

	// The structured copy has a value BSON cannot hold at all, and
	// without this the whole document is unwritable: the driver's
	// json.Number encoder tries Int64 and then Float64, and a literal
	// past float64's range - 1e400, say - fails both, so bson.Marshal
	// returns strconv's range error and session creation fails before
	// the request ever reaches a wallet. The exact JSON above holds that
	// literal perfectly well, which is the point of it; it is only the
	// legacy document-valued copy that has nowhere to put it.
	//
	// Dropped rather than approximated. BSON would take the value as
	// +Inf, and an old replica reading that would send a request with a
	// number nobody configured - a req param is an input to a proof, so
	// a wrong one is a wrong pseudonym computed in silence. Omitting the
	// legacy copy instead leaves an old replica with no query, which it
	// can only fail on. A replica that understands dcql_query_exact is
	// unaffected either way, since it prefers that copy.
	//
	// Note this is strictly better than the behaviour it replaces: before
	// the exact copy existed, such a request could not be stored by ANY
	// build, so no old replica is losing a session it used to be able to
	// serve.
	document.DCQLQuery = nil
	retried, retryErr := bson.Marshal(document)
	if retryErr != nil {
		// The query was not the cause. Report what actually failed.
		return nil, err
	}
	return retried, nil
}

// UnmarshalBSON prefers the exact copy when one is there.
//
// A document written before this change carries only dcql_query, and is
// read exactly as it was before - rounded, which is what that build did
// anyway. Nothing regresses; what is new is that a document written by a
// current replica comes back with its numbers intact.
func (a *AuthorizationContext) UnmarshalBSON(data []byte) error {
	type plain AuthorizationContext
	var document plain
	if err := bson.Unmarshal(data, &document); err != nil {
		return err
	}
	*a = AuthorizationContext(document)

	if a.DCQLQueryExact == "" {
		return nil
	}
	var exact openid4vp.DCQL
	if err := json.Unmarshal([]byte(a.DCQLQueryExact), &exact); err != nil {
		// Not fatal on its own - the rounded copy is still there and is
		// what an older build would have used - but it means the exact
		// copy was corrupted in storage, which is worth refusing rather
		// than silently falling back to a query whose numbers may differ
		// from the one that was sent.
		return fmt.Errorf("authorization context: the exact dcql query is unreadable: %w", err)
	}
	a.DCQLQuery = &exact
	return nil
}
