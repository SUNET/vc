package credential

import (
	"fmt"
	"sync"
	"time"
)

// StoredCredential represents a credential held in the wallet
type StoredCredential struct {
	// ID is a unique identifier for this stored credential
	ID string `json:"id"`
	// RawCredential is the raw credential string (SD-JWT, mdoc, etc.)
	RawCredential string `json:"raw_credential"`
	// Format is the credential format (e.g., "vc+sd-jwt", "mso_mdoc")
	Format string `json:"format"`
	// VCT is the verifiable credential type URN
	VCT string `json:"vct,omitempty"`
	// IssuerURL is the issuer that issued this credential
	IssuerURL string `json:"issuer_url"`
	// IssuedAt is when the credential was received
	IssuedAt time.Time `json:"issued_at"`
	// ScenarioName is the scenario that obtained this credential
	ScenarioName string `json:"scenario_name"`
	// NotificationID is the notification_id from the issuer (if any)
	NotificationID string `json:"notification_id,omitempty"`
	// TransactionID is the deferred transaction_id (if any)
	TransactionID string `json:"transaction_id,omitempty"`
}

// Store is a thread-safe in-memory credential store
type Store struct {
	mu          sync.RWMutex
	credentials map[string]*StoredCredential
	counter     int
}

// NewStore creates a new credential store
func NewStore() *Store {
	return &Store{
		credentials: make(map[string]*StoredCredential),
	}
}

// Add stores a credential and returns its ID
func (s *Store) Add(cred *StoredCredential) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	if cred.ID == "" {
		cred.ID = fmt.Sprintf("cred-%d", s.counter)
	}
	cred.IssuedAt = time.Now()
	s.credentials[cred.ID] = cred
	return cred.ID
}

// Get retrieves a credential by ID
func (s *Store) Get(id string) (*StoredCredential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cred, ok := s.credentials[id]
	return cred, ok
}

// List returns all stored credentials
func (s *Store) List() []*StoredCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*StoredCredential, 0, len(s.credentials))
	for _, cred := range s.credentials {
		result = append(result, cred)
	}
	return result
}

// FindByVCT returns credentials matching the given VCT
func (s *Store) FindByVCT(vct string) []*StoredCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*StoredCredential
	for _, cred := range s.credentials {
		if cred.VCT == vct {
			result = append(result, cred)
		}
	}
	return result
}

// FindByFormat returns credentials matching the given format
func (s *Store) FindByFormat(format string) []*StoredCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*StoredCredential
	for _, cred := range s.credentials {
		if cred.Format == format {
			result = append(result, cred)
		}
	}
	return result
}

// Delete removes a credential by ID
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credentials[id]; ok {
		delete(s.credentials, id)
		return true
	}
	return false
}

// Count returns the number of stored credentials
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.credentials)
}
