package cache

import (
	"time"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// IssuerStateResume is the exchange that replaces a one-shot issuer_state
// when a wallet takes up an issuer-initiated offer.
//
// A struct rather than a prepared AuthorizationContext because the two
// stores write it differently - MongoDB as a field-level $set alongside
// the $unset that claims the handle, the memory store as a mutation of
// the document it already holds - and both have to apply exactly the same
// set of fields for the two backends to behave alike.
type IssuerStateResume struct {
	// AuthSession is the handle the wallet continues the exchange with.
	AuthSession string

	// AuthSessionDPoPThumbprint binds that handle, and the authorization
	// code it ends with, to the key the challenge was sent with.
	AuthSessionDPoPThumbprint string

	// WalletClientID and WalletURI are the wallet's half of the exchange.
	WalletClientID string
	WalletURI      string

	// CodeChallenge and CodeChallengeMethod are the PKCE parameters the
	// Token Endpoint checks when the code is redeemed.
	CodeChallenge       string
	CodeChallengeMethod string

	// DCQLQuery is what the wallet is being asked to present.
	DCQLQuery *openid4vp.DCQL

	// ExpiresAt is the deadline the exchange is checked against, and
	// CreatedAt the anchor MongoDB's TTL index expires the document on.
	// Both move: a logical deadline outliving its physical document means
	// an exchange that vanishes with nothing having gone wrong.
	ExpiresAt int64
	CreatedAt time.Time
}

// applyTo writes the resumed exchange onto doc. Used by the memory store;
// the Mongo store builds the equivalent $set and the two must stay in
// step.
func (r *IssuerStateResume) applyTo(doc *AuthorizationContext) {
	doc.AuthSession = r.AuthSession
	doc.AuthSessionDPoPThumbprint = r.AuthSessionDPoPThumbprint
	doc.WalletClientID = r.WalletClientID
	doc.WalletURI = r.WalletURI
	doc.CodeChallenge = r.CodeChallenge
	doc.CodeChallengeMethod = r.CodeChallengeMethod
	doc.DCQLQuery = r.DCQLQuery
	doc.ExpiresAt = r.ExpiresAt
	doc.CreatedAt = r.CreatedAt
}
