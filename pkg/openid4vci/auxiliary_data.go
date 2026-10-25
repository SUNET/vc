package openid4vci

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Credential Auxiliary Data carries data that goes with a Credential at
// issuance and stays outside it
// (openid-4-verifiable-credential-issuance-auxiliary-data.md in
// sirosfoundation/nym_auth_rulebook).

// AuxiliaryDataTypeHashCommitment is the Auxiliary Data Type the
// extension defines.
const AuxiliaryDataTypeHashCommitment = "hash_commitment"

// HashCommitmentAlgSHA256 is the hash_commitment alg the extension
// defines.
const HashCommitmentAlgSHA256 = "sha-256"

// HashCommitment returns the alg hash of an opening.
func HashCommitment(alg string, opening []byte) ([]byte, error) {
	if len(opening) == 0 {
		return nil, errors.New("auxiliary data: the opening is empty")
	}
	if _, err := HashCommitmentSize(alg); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(opening)
	return sum[:], nil
}

// HashCommitmentSize returns the output length of alg.
func HashCommitmentSize(alg string) (int, error) {
	if alg != HashCommitmentAlgSHA256 {
		return 0, fmt.Errorf("auxiliary data: alg %q is not %s", alg, HashCommitmentAlgSHA256)
	}
	return sha256.Size, nil
}

// AuxiliaryDataEntry is one Auxiliary Data Entry. Its members other than
// Type are those of hash_commitment.
type AuxiliaryDataEntry struct {
	// Type is the Auxiliary Data Type.
	Type string `json:"type" yaml:"type" doc_example:"\"hash_commitment\""`

	// Alg is the hash function of a hash_commitment.
	Alg string `json:"alg,omitempty" yaml:"alg" doc_example:"\"sha-256\""`

	// Path is the claims path pointer of the claim that holds the
	// commitment.
	Path []string `json:"path,omitempty" yaml:"path" doc_example:"[\"eu.europa.ec.eudi.nym_auth.1\", \"ssc\"]"`

	// Opening is the base64url secret, in an entry the Credential Issuer
	// sends. It is a Secret Value.
	Opening string `json:"opening,omitempty" yaml:"opening,omitempty"`

	// Commitment is the base64url commitment, in an entry the Wallet
	// sends.
	Commitment string `json:"commitment,omitempty" yaml:"commitment,omitempty"`

	// Required, in a to_issuer entry of metadata, means the Wallet must
	// send it.
	Required bool `json:"required,omitempty" yaml:"required,omitempty"`

	// Encoding is how the claim at Path represents the commitment, in
	// metadata: base64url, base64 or hex text, or the bytes when empty.
	Encoding string `json:"encoding,omitempty" yaml:"encoding,omitempty" doc_example:"\"base64url\""`
}

// The text encodings of AuxiliaryDataEntry.Encoding.
const (
	CommitmentEncodingBase64URL = "base64url"
	CommitmentEncodingBase64    = "base64"
	CommitmentEncodingHex       = "hex"
)

// EncodeCommitment writes a commitment in a text encoding of
// AuxiliaryDataEntry.Encoding: base64url without padding, base64 with
// padding, or lowercase hex.
func EncodeCommitment(encoding string, commitment []byte) (string, error) {
	switch encoding {
	case CommitmentEncodingBase64URL:
		return base64.RawURLEncoding.EncodeToString(commitment), nil
	case CommitmentEncodingBase64:
		return base64.StdEncoding.EncodeToString(commitment), nil
	case CommitmentEncodingHex:
		return hex.EncodeToString(commitment), nil
	}
	return "", fmt.Errorf("auxiliary data: encoding %q is none of %s, %s and %s",
		encoding, CommitmentEncodingBase64URL, CommitmentEncodingBase64, CommitmentEncodingHex)
}

// AuxiliaryDataSupported is the auxiliary_data_supported parameter of a
// credential configuration.
type AuxiliaryDataSupported struct {
	// ToWallet lists the entries the Credential Issuer sends in each
	// response that carries Credentials.
	ToWallet []AuxiliaryDataEntry `json:"to_wallet,omitempty" yaml:"to_wallet,omitempty"`

	// ToIssuer lists the entries the Credential Issuer accepts in key
	// proofs.
	ToIssuer []AuxiliaryDataEntry `json:"to_issuer,omitempty" yaml:"to_issuer,omitempty"`
}

// AddAuxiliaryData adds entries to the response-level
// credential_metadata.
//
// The response may share its credential_metadata with the published
// issuer metadata, so the object is copied before it is written.
func (r *CredentialResponse) AddAuxiliaryData(entries ...AuxiliaryDataEntry) {
	metadata := CredentialMetadata{}
	if r.CredentialMetadata != nil {
		metadata = *r.CredentialMetadata
	}
	metadata.AuxiliaryData = append(slices.Clone(metadata.AuxiliaryData), entries...)
	r.CredentialMetadata = &metadata
}

// decodeWalletAuxiliaryData reads the auxiliary_data claim of a key proof:
// its hash_commitment entries, at most one per path. Entries of other types
// are ignored.
func decodeWalletAuxiliaryData(claim json.RawMessage) ([]AuxiliaryDataEntry, error) {
	if claim == nil {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(claim, &items); err != nil {
		return nil, fmt.Errorf("auxiliary_data: %w", err)
	}
	var entries []AuxiliaryDataEntry
	for i, item := range items {
		entry, recognized, err := decodeWalletEntry(item)
		if err != nil {
			return nil, fmt.Errorf("auxiliary_data[%d]: %w", i, err)
		}
		if !recognized {
			continue
		}
		if slices.ContainsFunc(entries, func(e AuxiliaryDataEntry) bool { return slices.Equal(e.Path, entry.Path) }) {
			return nil, fmt.Errorf("auxiliary_data[%d]: a second entry for %q", i, entry.Path)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// walletAbsentMembers are the hash_commitment members an entry from the
// Wallet must not carry, whatever their value: opening belongs to a
// response, encoding and required to metadata.
var walletAbsentMembers = []string{"opening", "encoding", "required"}

// decodeWalletEntry decodes one entry the Wallet sent. recognized is false
// for an entry of another type than hash_commitment.
func decodeWalletEntry(item json.RawMessage) (entry AuxiliaryDataEntry, recognized bool, err error) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(item, &head); err != nil {
		return AuxiliaryDataEntry{}, false, err
	}
	if head.Type != AuxiliaryDataTypeHashCommitment {
		return AuxiliaryDataEntry{}, false, nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(item, &members); err != nil {
		return AuxiliaryDataEntry{}, false, err
	}
	for _, name := range walletAbsentMembers {
		if _, present := members[name]; present {
			return AuxiliaryDataEntry{}, false, fmt.Errorf("an entry from the Wallet carries no %q", name)
		}
	}
	if err := json.Unmarshal(item, &entry); err != nil {
		return AuxiliaryDataEntry{}, false, err
	}
	return entry, true, nil
}

// jwtPayload decodes the payload of a compact JWT into v, without
// verifying its signature.
func jwtPayload(token string, v any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	return json.Unmarshal(payload, v)
}
