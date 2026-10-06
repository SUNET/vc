package oidcrp

import (
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// credentials is one client registration, complete and immutable.
//
// The oauth2 config and the ID token verifier belong together: the verifier
// checks `aud` against the client id the config authenticates with. They
// used to be two fields replaced one after the other while request handlers
// read them without a lock, so a callback could exchange a code with one
// client and then verify the ID token against another - and that is a data
// race as well as a logic error. Publishing them as one pointer makes a
// reader see a consistent pair or the previous pair, never a mixture.
type credentials struct {
	clientID  string
	config    *oauth2.Config
	verifier  *oidc.IDTokenVerifier
	expiresAt time.Time

	// renewNotBefore keeps a short-lived secret from being replaced on
	// every request. An OP that issues secrets lasting less than the
	// renewal lead time would otherwise never produce one this service
	// considers fresh, so each request would register another client.
	renewNotBefore time.Time
}

// needsRenewal reports whether this registration should be replaced now.
func (c *credentials) needsRenewal(now time.Time) bool {
	if c == nil {
		return false
	}
	if c.expiresAt.IsZero() {
		// client_secret_expires_at: 0 - never expires (RFC 7591 §3.2.1).
		return false
	}
	if now.Before(c.renewNotBefore) {
		return false
	}
	return !now.Before(c.expiresAt.Add(-clientSecretRenewBefore))
}

// credentialSet holds the registration in use plus the ones a flow started
// under and may still come back to.
//
// Retaining the old one matters because an authorization code is issued to
// a specific client: a flow that began before a renewal must finish on the
// client that began it, or the OP rejects the exchange.
//
// This is a per-process cache, bounded by how long a flow can take
// (OIDCRP.SessionDuration). It is not what keeps a registration available
// to other replicas - that is the store, which prunes by secret expiry, and
// which Service.credentialsForSession falls back to.
type credentialSet struct {
	mu        sync.RWMutex
	current   *credentials
	retired   map[string]*credentials
	retiredAt map[string]time.Time
	// retainFor is how long a superseded registration stays usable. It
	// should cover the longest authorization flow, which is the session
	// lifetime.
	retainFor time.Duration
}

func newCredentialSet(retainFor time.Duration) *credentialSet {
	return &credentialSet{
		retired:   map[string]*credentials{},
		retiredAt: map[string]time.Time{},
		retainFor: retainFor,
	}
}

// current returns the registration new flows should start under.
func (s *credentialSet) load() *credentials {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// forClient returns the registration a flow started under, or the current
// one when the session names none. A clientID this process has never seen
// returns the current registration too; callers that can do better - see
// Service.credentialsForSession, which reads the shared store - check the
// returned clientID.
func (s *credentialSet) forClient(clientID string) *credentials {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.current != nil && (clientID == "" || s.current.clientID == clientID) {
		return s.current
	}
	if c, ok := s.retired[clientID]; ok {
		return c
	}
	return s.current
}

// retain records a registration this process did not publish, so a second
// callback for the same flow does not have to read it back again. It does
// not become current.
func (s *credentialSet) retain(c *credentials) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.current != nil && s.current.clientID == c.clientID {
		return
	}
	s.retired[c.clientID] = c
	s.retiredAt[c.clientID] = time.Now()
}

// store publishes a registration, retiring the one it replaces.
func (s *credentialSet) store(c *credentials) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, at := range s.retiredAt {
		if now.Sub(at) > s.retainFor {
			delete(s.retired, id)
			delete(s.retiredAt, id)
		}
	}

	if s.current != nil && s.current.clientID != c.clientID {
		s.retired[s.current.clientID] = s.current
		s.retiredAt[s.current.clientID] = now
	}

	s.current = c
}
