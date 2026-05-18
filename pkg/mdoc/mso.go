// Package mdoc provides Mobile Security Object (MSO) generation per ISO/IEC 18013-5:2021.
package mdoc

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"hash"
	"maps"
	"slices"
	"sort"
	"time"
)

// DigestAlgorithm represents the hash algorithm used for digests.
type DigestAlgorithm string

const (
	// DigestAlgorithmSHA256 uses SHA-256 for digest computation.
	DigestAlgorithmSHA256 DigestAlgorithm = "SHA-256"
	// DigestAlgorithmSHA384 uses SHA-384 for digest computation.
	DigestAlgorithmSHA384 DigestAlgorithm = "SHA-384"
	// DigestAlgorithmSHA512 uses SHA-512 for digest computation.
	DigestAlgorithmSHA512 DigestAlgorithm = "SHA-512"
)

// MSOIssuerSignedItem represents a single data element with its digest ID and random salt.
// Per ISO 18013-5 section 9.1.2.4, this is the structure that gets hashed.
// This is internal to MSO generation; the canonical IssuerSignedItem is in mdoc.go.
type MSOIssuerSignedItem struct {
	DigestID     uint   `cbor:"digestID"`
	Random       []byte `cbor:"random"`
	ElementID    string `cbor:"elementIdentifier"`
	ElementValue any    `cbor:"elementValue"`
}

// IssuerNameSpaces maps namespace to a list of IssuerSignedItem (as tagged CBOR).
type IssuerNameSpaces map[string][]TaggedCBOR

// TaggedCBOR represents CBOR data wrapped with tag 24 (encoded CBOR data item).
type TaggedCBOR struct {
	_    struct{} `cbor:",toarray"`
	Data []byte
}

// ValueDigests maps digest ID to the actual digest bytes.
type ValueDigests map[uint][]byte

// DigestIDMapping maps namespace to ValueDigests.
type DigestIDMapping map[string]ValueDigests

// MSOBuilder builds a Mobile Security Object.
type MSOBuilder struct {
	docType         string
	digestAlgorithm DigestAlgorithm
	validFrom       time.Time
	validUntil      time.Time
	deviceKey       *COSEKey
	signerKey       crypto.Signer
	signerCert      *x509.Certificate
	certChain       []*x509.Certificate
	namespaces      map[string][]MSOIssuerSignedItem
	digestIDCounter map[string]uint
}

// NewMSOBuilder creates a new MSO builder.
func NewMSOBuilder(docType string) *MSOBuilder {
	builder := &MSOBuilder{
		docType:         docType,
		digestAlgorithm: DigestAlgorithmSHA256,
		namespaces:      make(map[string][]MSOIssuerSignedItem),
		digestIDCounter: make(map[string]uint),
	}
	return builder
}

// WithDigestAlgorithm sets the digest algorithm.
func (b *MSOBuilder) WithDigestAlgorithm(alg DigestAlgorithm) *MSOBuilder {
	b.digestAlgorithm = alg
	return b
}

// WithValidity sets the validity period.
func (b *MSOBuilder) WithValidity(from, until time.Time) *MSOBuilder {
	b.validFrom = from
	b.validUntil = until
	return b
}

// WithDeviceKey sets the device key (holder's key).
func (b *MSOBuilder) WithDeviceKey(key *COSEKey) *MSOBuilder {
	b.deviceKey = key
	return b
}

// WithSigner sets the document signer key and certificate chain.
func (b *MSOBuilder) WithSigner(key crypto.Signer, certChain []*x509.Certificate) *MSOBuilder {
	b.signerKey = key
	if len(certChain) > 0 {
		b.signerCert = certChain[0]
	}
	b.certChain = certChain
	return b
}

// AddDataElement adds a data element to the MSO.
func (b *MSOBuilder) AddDataElement(namespace, elementID string, value any) error {
	// Generate random salt (at least 16 bytes per spec)
	randomSalt := make([]byte, 32)
	if _, err := rand.Read(randomSalt); err != nil {
		return fmt.Errorf("failed to generate random salt: %w", err)
	}

	// Get next digest ID for this namespace
	digestID := b.digestIDCounter[namespace]
	b.digestIDCounter[namespace]++

	item := MSOIssuerSignedItem{
		DigestID:     digestID,
		Random:       randomSalt,
		ElementID:    elementID,
		ElementValue: value,
	}

	b.namespaces[namespace] = append(b.namespaces[namespace], item)
	return nil
}

// AddDataElementWithRandom adds a data element with a specific random value (for testing).
func (b *MSOBuilder) AddDataElementWithRandom(namespace, elementID string, value any, random []byte) error {
	digestID := b.digestIDCounter[namespace]
	b.digestIDCounter[namespace]++

	item := MSOIssuerSignedItem{
		DigestID:     digestID,
		Random:       random,
		ElementID:    elementID,
		ElementValue: value,
	}

	b.namespaces[namespace] = append(b.namespaces[namespace], item)
	return nil
}

// Build creates the signed MSO and IssuerNameSpaces.
func (b *MSOBuilder) Build() (*COSESign1, map[string][]cbor.Tag, error) {
	if b.signerKey == nil {
		return nil, nil, fmt.Errorf("signer key is required")
	}
	if b.deviceKey == nil {
		return nil, nil, fmt.Errorf("device key is required")
	}
	if b.validFrom.IsZero() || b.validUntil.IsZero() {
		return nil, nil, fmt.Errorf("validity period is required")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	issuerNameSpaces := make(map[string][]cbor.Tag)
	valueDigests := make(map[string]map[uint][]byte)
	for namespace, items := range b.namespaces {
		currentNSTaggedItems := make([]cbor.Tag, 0, len(items))
		nsValueDigests := make(map[uint][]byte)

		for _, item := range items {
			// Encode the inner map (MSOIssuerSignedItem)
			innerEncoded, err := encoder.Marshal(item)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to encode item %s: %w", item.ElementID, err)
			}

			// Wrap in Tag 24
			wrapper := cbor.Tag{Number: TagEncodedCBOR, Content: innerEncoded}
			// Encode the WRAPPER itself
			wrapperEncoded, err := encoder.Marshal(wrapper)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to encode wrapper: %w", err)
			}

			// Save the wrapper for the IssuerSigned structure
			currentNSTaggedItems = append(currentNSTaggedItems, wrapper)

			// Compute digest of the ENTIRE wrapperEncoded block
			digest, err := b.computeDigest(wrapperEncoded)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to compute digest for %s: %w", item.ElementID, err)
			}
			nsValueDigests[item.DigestID] = digest
		}

		// Store results for this namespace
		issuerNameSpaces[namespace] = currentNSTaggedItems
		valueDigests[namespace] = nsValueDigests
	}

	signedTime := time.Now().UTC().Format(time.RFC3339)
	validFromStr := b.validFrom.UTC().Format(time.RFC3339)
	validUntilStr := b.validUntil.UTC().Format(time.RFC3339)

	// Get device key bytes
	deviceKeyBytes, err := b.deviceKey.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode device key: %w", err)
	}

	mso := map[string]any{
		"version":         "1.0",
		"digestAlgorithm": string(b.digestAlgorithm),
		"docType":         b.docType,
		"valueDigests":    valueDigests,
		"deviceKeyInfo": map[string]any{
			"deviceKey": deviceKeyBytes,
		},
		"validityInfo": map[string]any{
			"signed":     cbor.Tag{Number: 0, Content: signedTime},
			"validFrom":  cbor.Tag{Number: 0, Content: validFromStr},
			"validUntil": cbor.Tag{Number: 0, Content: validUntilStr},
		},
	}

	// Encode MSO as CBOR
	msoBytes, err := encoder.Marshal(mso)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode MSO: %w", err)
	}

	// MSO must also be wrapped in Tag 24 before signing
	msoTagged := cbor.Tag{Number: TagEncodedCBOR, Content: msoBytes}

	msoTaggedBytes, err := encoder.Marshal(msoTagged)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode tagged MSO: %w", err)
	}

	// Determine algorithm from signer key
	algorithm, err := AlgorithmForKey(b.signerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine algorithm: %w", err)
	}

	// Sign the MSO using COSE_Sign1
	certDER := make([][]byte, 0, len(b.certChain))
	for _, cert := range b.certChain {
		certDER = append(certDER, cert.Raw)
	}

	signedMSO, err := Sign1(msoTaggedBytes, b.signerKey, algorithm, certDER, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign MSO: %w", err)
	}

	return signedMSO, issuerNameSpaces, nil
}

// computeDigest computes the digest of data using the configured algorithm.
func (b *MSOBuilder) computeDigest(data []byte) ([]byte, error) {
	var h hash.Hash
	switch b.digestAlgorithm {
	case DigestAlgorithmSHA256:
		h = sha256.New()
	case DigestAlgorithmSHA384:
		h = sha512.New384()
	case DigestAlgorithmSHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported digest algorithm: %s", b.digestAlgorithm)
	}

	h.Write(data)
	return h.Sum(nil), nil
}

// convertDigestMapping converts the internal digest mapping to the MSO format.
func (b *MSOBuilder) convertDigestMapping(mapping DigestIDMapping) map[string]map[uint][]byte {
	result := make(map[string]map[uint][]byte, len(mapping))
	for ns, digests := range mapping {
		nsDigests := make(map[uint][]byte, len(digests))
		maps.Copy(nsDigests, digests)
		result[ns] = nsDigests
	}
	return result
}

// VerifyMSO verifies a signed MSO against the issuer certificate.
func VerifyMSO(signedMSO *COSESign1, issuerCert *x509.Certificate) (*MobileSecurityObject, error) {
	// Verify the COSE_Sign1 signature
	if err := Verify1(signedMSO, signedMSO.Payload, issuerCert.PublicKey, nil); err != nil {
		return nil, fmt.Errorf("MSO signature verification failed: %w", err)
	}

	// Decode the MSO payload
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}
	var mso MobileSecurityObject
	if err := encoder.Unmarshal(signedMSO.Payload, &mso); err != nil {
		return nil, fmt.Errorf("failed to decode MSO: %w", err)
	}

	return &mso, nil
}

// VerifyDigest verifies that an IssuerSignedItem matches its digest in the MSO.
func VerifyDigest(mso *MobileSecurityObject, namespace string, item *IssuerSignedItem) error {
	// Get the expected digest from MSO
	nsDigests, ok := mso.ValueDigests[namespace]
	if !ok {
		return fmt.Errorf("namespace %s not found in MSO", namespace)
	}

	expectedDigest, ok := nsDigests[item.DigestID]
	if !ok {
		return fmt.Errorf("digest ID %d not found in namespace %s", item.DigestID, namespace)
	}

	// Compute the actual digest
	encoder, err := NewCBOREncoder()
	if err != nil {
		return fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	itemBytes, err := encoder.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to encode item: %w", err)
	}

	taggedItem := cbor.Tag{
		Number:  TagEncodedCBOR,
		Content: itemBytes,
	}

	encoded, err := encoder.Marshal(taggedItem)
	if err != nil {
		return fmt.Errorf("failed to encode tagged item: %w", err)
	}

	var actualDigest []byte
	switch DigestAlgorithm(mso.DigestAlgorithm) {
	case DigestAlgorithmSHA256:
		h := sha256.Sum256(encoded)
		actualDigest = h[:]
	case DigestAlgorithmSHA384:
		h := sha512.Sum384(encoded)
		actualDigest = h[:]
	case DigestAlgorithmSHA512:
		h := sha512.Sum512(encoded)
		actualDigest = h[:]
	default:
		return fmt.Errorf("unsupported digest algorithm: %s", mso.DigestAlgorithm)
	}

	// Compare digests
	if hex.EncodeToString(actualDigest) != hex.EncodeToString(expectedDigest) {
		return fmt.Errorf("digest mismatch for %s/%s", namespace, item.ElementIdentifier)
	}

	return nil
}

// ValidateMSOValidity checks if the MSO is currently valid.
func ValidateMSOValidity(mso *MobileSecurityObject) error {
	now := time.Now().UTC()

	if now.Before(mso.ValidityInfo.ValidFrom) {
		return fmt.Errorf("MSO not yet valid, valid from: %s", mso.ValidityInfo.ValidFrom)
	}

	if now.After(mso.ValidityInfo.ValidUntil) {
		return fmt.Errorf("MSO expired, valid until: %s", mso.ValidityInfo.ValidUntil)
	}

	return nil
}

// GetDigestIDs returns all digest IDs for a namespace in sorted order.
func GetDigestIDs(mso *MobileSecurityObject, namespace string) []uint {
	nsDigests, ok := mso.ValueDigests[namespace]
	if !ok {
		return nil
	}

	ids := make([]uint, 0, len(nsDigests))
	for id := range nsDigests {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// MSOInfo contains parsed information from an MSO for display purposes.
type MSOInfo struct {
	Version         string
	DigestAlgorithm string
	DocType         string
	Signed          time.Time
	ValidFrom       time.Time
	ValidUntil      time.Time
	Namespaces      []string
	DigestCount     int
}

// GetMSOInfo extracts display information from an MSO.
func GetMSOInfo(mso *MobileSecurityObject) MSOInfo {
	namespaces := make([]string, 0, len(mso.ValueDigests))
	digestCount := 0
	for ns, digests := range mso.ValueDigests {
		namespaces = append(namespaces, ns)
		digestCount += len(digests)
	}
	sort.Strings(namespaces)

	return MSOInfo{
		Version:         mso.Version,
		DigestAlgorithm: mso.DigestAlgorithm,
		DocType:         mso.DocType,
		Signed:          mso.ValidityInfo.Signed,
		ValidFrom:       mso.ValidityInfo.ValidFrom,
		ValidUntil:      mso.ValidityInfo.ValidUntil,
		Namespaces:      namespaces,
		DigestCount:     digestCount,
	}
}
