package db

import (
	"context"
	"errors"
	"time"

	"github.com/SUNET/vc/pkg/model"
)

// CredentialOfferStore defines the interface for credential offer operations
type CredentialOfferStore interface {
	Save(ctx context.Context, doc *CredentialOfferDocument) error
	Get(ctx context.Context, uuid string) (*CredentialOfferDocument, error)
	Delete(ctx context.Context, uuid string) error
}

// DatastoreStore defines the interface for datastore operations
type DatastoreStore interface {
	// Count returns the (possibly approximate) number of documents in the datastore.
	Count(ctx context.Context) (int64, error)
	Save(ctx context.Context, doc *model.CompleteDocument) error
	SaveMany(ctx context.Context, docs []*model.CompleteDocument) error
	AddIdentity(ctx context.Context, query *AddIdentityQuery) error
	DeleteIdentity(ctx context.Context, query *DeleteIdentityQuery) error
	Delete(ctx context.Context, doc *model.MetaData) error
	Get(ctx context.Context, meta *model.MetaData) (*model.Document, error)
	GetByIdentity(ctx context.Context, scope, identityMappingID string) (map[string]*model.CompleteDocument, error)
	List(ctx context.Context, query *ListQuery) ([]*model.DocumentList, error)
	Replace(ctx context.Context, doc *model.CompleteDocument) error
	GetByKey(ctx context.Context, authenticSource, scope, documentID string) (*model.CompleteDocument, error)
	DeleteByKey(ctx context.Context, authenticSource, scope, documentID string) error
	Search(ctx context.Context, query *SearchDocumentsQuery) ([]*model.CompleteDocument, error)
	ListAuthenticSources(ctx context.Context) ([]string, error)
}

// IdentityMappingStore defines the interface for identity mapping operations
type IdentityMappingStore interface {
	// Count returns the (possibly approximate) number of identity mappings.
	Count(ctx context.Context) (int64, error)
	CreateMapping(ctx context.Context, mapping *model.IdentityMapping) error
	CreateMappings(ctx context.Context, mappings []*model.IdentityMapping) error
	EnsureMapping(ctx context.Context, mapping *model.IdentityMapping) error
	ResolveMapping(ctx context.Context, query *ResolveMappingQuery) (string, error)
	UpdateMapping(ctx context.Context, mapping *model.IdentityMapping) error
	DeleteMapping(ctx context.Context, query *DeleteMappingQuery) error
	SearchMappings(ctx context.Context, query *SearchMappingsQuery) ([]*model.IdentityMapping, error)
}

// DynamicRegistrationStore defines the interface for OIDC dynamic client registration operations
type DynamicRegistrationStore interface {
	Save(ctx context.Context, creds *DynamicRegistrationCredentials) error
	Get(ctx context.Context) (*DynamicRegistrationCredentials, error)
	// GetByClientID returns one stored registration by client_id, or nil.
	// An authorization code is issued to a specific client, so a callback
	// that lands on a different HA replica than the one that started the
	// flow has to be able to find the registration it started under.
	GetByClientID(ctx context.Context, clientID string) (*DynamicRegistrationCredentials, error)

	// PruneExpiredRegistrations removes stored registrations whose client
	// secret had already expired at `now`, except keepClientID.
	//
	// Expiry, not age, is the safe predicate. "Registered long ago" says
	// nothing about whether a registration is still in use: in HA another
	// replica can be running on an hours-old registration as its current
	// one, and deleting it would strand every callback that lands here. A
	// secret that has expired cannot be redeemed by anyone, so removing its
	// row takes nothing away from any replica.
	//
	// Registrations whose secret never expires are never pruned, which is
	// the price of not coordinating; they accumulate one row per renewal,
	// and an OP issuing non-expiring secrets gives no reason to renew.
	//
	// Idempotent on purpose: the save and the prune cannot be made atomic
	// across both backends, so a crash between them leaves extra rows and a
	// later renewal clears them. Get orders by registered_at, so startup
	// does not depend on the prune having happened.
	PruneExpiredRegistrations(ctx context.Context, keepClientID string, now time.Time) error
}

// UniqueCommitmentStore holds one commitment per key value for each unique
// hash_commitment entry of Credential Auxiliary Data (section 6.4, step 5).
// The database arbitrates between replicas: the first commitment stored for a
// key is the one every replica reads back.
type UniqueCommitmentStore interface {
	// Accept stores commitment for key when key holds none, and returns the
	// commitment key holds afterwards.
	Accept(ctx context.Context, key UniqueCommitmentKey, commitment []byte, at time.Time) ([]byte, error)
	// Find returns the record key holds, or ErrNoDocuments.
	Find(ctx context.Context, key UniqueCommitmentKey) (UniqueCommitmentRecord, error)
	// Reset records the operator approval and removes the commitment key
	// holds. ErrNoDocuments when key holds none; ErrResetEvidenceUsed when
	// the approval's evidence reference already reset another commitment.
	Reset(ctx context.Context, key UniqueCommitmentKey, approval UniqueCommitmentReset) error
}

// UniqueCommitmentKey names the commitment of one key value for one entry.
type UniqueCommitmentKey struct {
	Scope string
	// Path is the claims path of the entry.
	Path []string
	// KeyHash is the hash of the key values.
	KeyHash []byte
}

// UniqueCommitmentRecord is what the store holds for a key.
type UniqueCommitmentRecord struct {
	// AcceptedAt is when the commitment was recorded.
	AcceptedAt time.Time
}

// UniqueCommitmentReset is the operator approval behind a reset.
type UniqueCommitmentReset struct {
	ApprovedBy  string
	EvidenceRef string
	At          time.Time
}

// ErrResetEvidenceUsed is returned when an evidence reference already reset
// an earlier commitment of the same key.
var ErrResetEvidenceUsed = errors.New("this reference already reset an earlier commitment")

// Ensure concrete types implement the interfaces
var (
	_ CredentialOfferStore     = (*CredentialOfferColl)(nil)
	_ DatastoreStore           = (*DatastoreColl)(nil)
	_ IdentityMappingStore     = (*IdentityMappingsColl)(nil)
	_ DynamicRegistrationStore = (*DynamicRegistrationColl)(nil)
	_ UniqueCommitmentStore    = (*UniqueCommitments)(nil)
)
