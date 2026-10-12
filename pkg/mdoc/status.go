// Package mdoc implements the ISO/IEC 18013-5:2021 Mobile Driving Licence (mDL) data model.
package mdoc

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/SUNET/vc/pkg/tokenstatuslist"
)

// StatusCheckResult contains the result of a credential status check.
type StatusCheckResult struct {
	// Status is the credential status (valid, invalid, suspended).
	Status CredentialStatus
	// StatusCode is the raw status code from the status list.
	StatusCode uint8
	// CheckedAt is the timestamp when the status was checked.
	CheckedAt time.Time
	// StatusListURI is the URI of the status list that was checked.
	StatusListURI string
	// Index is the index in the status list.
	Index int64
}

// CredentialStatus represents the status of a credential.
type CredentialStatus int

const (
	// CredentialStatusValid indicates the credential is valid.
	CredentialStatusValid CredentialStatus = iota
	// CredentialStatusInvalid indicates the credential has been revoked.
	CredentialStatusInvalid
	// CredentialStatusSuspended indicates the credential is temporarily suspended.
	CredentialStatusSuspended
	// CredentialStatusUnknown indicates the status could not be determined.
	CredentialStatusUnknown
)

// String returns a string representation of the credential status.
func (s CredentialStatus) String() string {
	switch s {
	case CredentialStatusValid:
		return "valid"
	case CredentialStatusInvalid:
		return "invalid"
	case CredentialStatusSuspended:
		return "suspended"
	default:
		return "unknown"
	}
}

// StatusReference contains the status list reference embedded in an mDL.
// This follows the draft-ietf-oauth-status-list specification.
type StatusReference struct {
	// URI is the URI of the Status List Token.
	URI string `json:"uri" cbor:"uri"`
	// Index is the index within the status list for this credential.
	Index int64 `json:"idx" cbor:"idx"`
}

// mapStatusCode maps a raw status code to a CredentialStatus.
func mapStatusCode(code uint8) CredentialStatus {
	switch code {
	case tokenstatuslist.StatusValid:
		return CredentialStatusValid
	case tokenstatuslist.StatusInvalid:
		return CredentialStatusInvalid
	case tokenstatuslist.StatusSuspended:
		return CredentialStatusSuspended
	default:
		return CredentialStatusUnknown
	}
}

// StatusManager manages credential status for an issuer.
type StatusManager struct {
	statusList *tokenstatuslist.StatusList
	nextIndex  int64
	uri        string
}

// NewStatusManager creates a new StatusManager for issuing credentials with status.
func NewStatusManager(uri string, initialSize int) *StatusManager {
	statuses := make([]uint8, initialSize)
	// Initialize all to valid
	for i := range statuses {
		statuses[i] = tokenstatuslist.StatusValid
	}

	return &StatusManager{
		statusList: tokenstatuslist.NewWithConfig(statuses, "", uri),
		nextIndex:  0,
		uri:        uri,
	}
}

// AllocateIndex allocates the next available index for a new credential.
func (sm *StatusManager) AllocateIndex() (int64, error) {
	if sm.nextIndex >= int64(sm.statusList.Len()) {
		return 0, errors.New("status list is full")
	}

	index := sm.nextIndex
	sm.nextIndex++
	return index, nil
}

// GetStatusReference returns a StatusReference for a credential at the given index.
func (sm *StatusManager) GetStatusReference(index int64) *StatusReference {
	return &StatusReference{
		URI:   sm.uri,
		Index: index,
	}
}

// Revoke marks a credential as revoked (invalid).
func (sm *StatusManager) Revoke(index int64) error {
	if index < 0 || index >= int64(sm.statusList.Len()) {
		return errors.New("index out of range")
	}
	return sm.statusList.Set(int(index), tokenstatuslist.StatusInvalid)
}

// Suspend marks a credential as suspended.
func (sm *StatusManager) Suspend(index int64) error {
	if index < 0 || index >= int64(sm.statusList.Len()) {
		return errors.New("index out of range")
	}
	return sm.statusList.Set(int(index), tokenstatuslist.StatusSuspended)
}

// Reinstate marks a suspended credential as valid again.
func (sm *StatusManager) Reinstate(index int64) error {
	if index < 0 || index >= int64(sm.statusList.Len()) {
		return errors.New("index out of range")
	}
	return sm.statusList.Set(int(index), tokenstatuslist.StatusValid)
}

// GetStatus returns the current status of a credential.
func (sm *StatusManager) GetStatus(index int64) (CredentialStatus, error) {
	if index < 0 || index >= int64(sm.statusList.Len()) {
		return CredentialStatusUnknown, errors.New("index out of range")
	}
	code, err := sm.statusList.Get(int(index))
	if err != nil {
		return CredentialStatusUnknown, err
	}
	return mapStatusCode(code), nil
}

// StatusList returns the underlying status list for token generation.
func (sm *StatusManager) StatusList() *tokenstatuslist.StatusList {
	return sm.statusList
}

// ErrNoStatusReference reports that a document carries no revocation
// reference at all, which is a normal credential rather than a failure. It
// is distinct from an unreadable reference, which is an error.
var ErrNoStatusReference = errors.New("no status reference found")

// ExtractMSOStatusReference extracts the status reference a VERIFIER may
// act on: the MSO's status parameter (draft-ietf-oauth-status-list Section
// 6.3) and nothing else.
//
// The MSO is issuer-signed as a whole and is not subject to selective
// disclosure, so its presence or absence is a fact about the credential.
// A "status" issuer-signed DATA ELEMENT is not: the holder chooses which
// elements to present, so a revoked credential whose only reference lives
// there is presented with the reference simply left out, and the verifier
// sees a credential that is not revocable. The reference is authentic when
// it does arrive - it is digest-covered by the MSO - but its ABSENCE means
// nothing, and absence is the case an adversary controls.
//
// Nor can the absence be detected. The MSO's ValueDigests name every
// issuer-signed element by digestID, so a verifier can tell that elements
// were withheld, but not WHICH - the identifier lives inside the element it
// cannot see. There is no check to add here.
//
// So the fallback is not used for verification at all. It only ever caught
// a holder who chose to be caught, and leaving it in made vc's revocation
// coverage look uniform across mdoc issuers when it is not. An issuer that
// wants its mdocs revocable must put the reference in the MSO; vc's own
// issuance always has (see mso.go).
//
// ExtractStatusReference keeps the fallback for diagnostic callers - see
// its own comment.
func ExtractMSOStatusReference(doc *DocumentMdoc) (*StatusReference, error) {
	if doc == nil {
		return nil, errors.New("document is nil")
	}
	ref, err := statusFromMSO(doc)
	if err != nil {
		// The MSO carries a status parameter that cannot be read. That is
		// not the same as carrying none: the issuer signed something here,
		// so the credential claims to be revocable and its state is
		// unknown. Reporting "absent" would make it verify as permanently
		// valid.
		return nil, err
	}
	if ref == nil {
		return nil, ErrNoStatusReference
	}
	return ref, nil
}

// ExtractStatusReference extracts the status reference from a Document.
//
// NOT FOR VERIFICATION. Use ExtractMSOStatusReference there, and read its
// comment for why.
//
// The MSO's status parameter (draft-ietf-oauth-status-list Section 6.3) is
// the canonical location and is checked first. A "status" issuer-signed data
// element is accepted as a fallback because implementations that predate
// Section 6.3 put it there - but it is strictly weaker: a data element is
// subject to selective disclosure, so a holder can simply not present it,
// and a verifier cannot tell that it did.
//
// That is tolerable for a diagnostic over documents an operator supplies -
// developer_tools/scripts/tsl_checker, which is asking "where does this
// document say its status lives" rather than "may I accept this
// credential". It is not tolerable on a verification path, where the holder
// is the one choosing what to show.
//
// This function does not verify anything. The caller must have verified the
// document before trusting what comes back.
func ExtractStatusReference(doc *DocumentMdoc) (*StatusReference, error) {
	if doc == nil {
		return nil, errors.New("document is nil")
	}

	ref, err := statusFromMSO(doc)
	if err != nil {
		// The MSO carries a status parameter that cannot be read. That is
		// not the same as carrying none: the issuer signed something here,
		// so the credential claims to be revocable and its state is
		// unknown. Reporting "absent" would make it verify as permanently
		// valid.
		return nil, err
	}
	if ref != nil {
		return ref, nil
	}

	// Look for status reference in issuer signed items
	for _, items := range doc.IssuerSigned.NameSpaces {
		for _, item := range items {
			var signedItem IssuerSignedItem
			var found bool

			switch v := item.(type) {
			case IssuerSignedItem:
				signedItem = v
				found = true
			case *IssuerSignedItem:
				if v != nil {
					signedItem = *v
					found = true
				}
			case cbor.Tag:
				// Tag 24 unwrapping: Unmarshal the content into the struct
				contentBytes, ok := v.Content.([]byte)
				if ok {
					if err := cbor.Unmarshal(contentBytes, &signedItem); err == nil {
						found = true
					}
				}
			case []byte:
				// Handle cases where it's already a raw byte slice
				if err := cbor.Unmarshal(v, &signedItem); err == nil {
					found = true
				}
			}

			// If successfully resolved an IssuerSignedItem, check for the status element
			if found && signedItem.ElementIdentifier == "status" {
				ref, ok := parseStatusElement(signedItem.ElementValue)
				if ok {
					return ref, nil
				}
			}
		}
	}

	return nil, ErrNoStatusReference
}

// parseStatusElement parses a status element value into a StatusReference.
func parseStatusElement(value any) (*StatusReference, bool) {
	m, ok := value.(map[string]any)
	if !ok {
		// Try map[any]any which CBOR might produce
		if mAny, ok := value.(map[any]any); ok {
			m = make(map[string]any)
			for k, v := range mAny {
				if ks, ok := k.(string); ok {
					m[ks] = v
				}
			}
		} else {
			return nil, false
		}
	}

	statusList, ok := m["status_list"].(map[string]any)
	if !ok {
		// Try map[any]any
		if slAny, ok := m["status_list"].(map[any]any); ok {
			statusList = make(map[string]any)
			for k, v := range slAny {
				if ks, ok := k.(string); ok {
					statusList[ks] = v
				}
			}
		} else {
			return nil, false
		}
	}

	uri, ok := statusList["uri"].(string)
	if !ok {
		return nil, false
	}

	var index int64
	switch idx := statusList["idx"].(type) {
	case int64:
		index = idx
	case int:
		index = int64(idx)
	case uint64:
		if idx > math.MaxInt64 {
			return nil, false
		}
		index = int64(idx)
	case float64:
		index = int64(idx)
	default:
		return nil, false
	}

	return &StatusReference{
		URI:   uri,
		Index: index,
	}, true
}

// statusFromMSO reads the MSO's status parameter.
//
// (nil, nil) means the MSO carries no status parameter, so the data-element
// fallback is still worth trying. A non-nil error means it carries one that
// cannot be used, which must not be reported as absence - see
// ExtractStatusReference.
//
// A document whose IssuerAuth or MSO will not decode at all is treated as
// "no status": that document fails verification for its own reasons long
// before anything asks about revocation, and reporting it here would
// replace a precise error with a misleading one.
func statusFromMSO(doc *DocumentMdoc) (*StatusReference, error) {
	sign1, err := ParseIssuerAuth(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, nil
	}
	mso, err := DecodeMSOPayload(sign1)
	if err != nil {
		return nil, nil
	}
	if mso.Status == nil {
		return nil, nil
	}
	if mso.Status.StatusList == nil {
		return nil, errors.New("mdoc MSO carries a status parameter with no status_list member")
	}
	ref := *mso.Status.StatusList
	if ref.URI == "" {
		return nil, errors.New("mdoc MSO status_list has no uri, so the list cannot be resolved")
	}
	if ref.Index < 0 {
		return nil, fmt.Errorf("mdoc MSO status_list has a negative index (%d)", ref.Index)
	}
	return &ref, nil
}
