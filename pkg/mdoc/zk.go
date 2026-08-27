package mdoc

// This file implements the wire-format parsing side of "mso_mdoc_zk"
// presentations: multipaz's `zkDocuments` extension to the standard ISO
// 18013-5 DeviceResponse, used to carry a zero-knowledge (Longfellow)
// proof-of-possession + optional pairwise pseudonym (PPID) instead of a
// normal IssuerSigned/DeviceSigned document.
//
// The wire shapes here were reverse-engineered from multipaz's own Kotlin
// implementation (multipaz/mdoc/zkp/ZkDocument.kt and ZkDocumentData.kt),
// which is the reference this org's wallets (siros-sdk-kotlin/swift) and
// verifiers interop-tested against. A ZK-wrapped DeviceResponse looks like:
//
//	{
//	  "version": "1.0",
//	  "status": 0,
//	  "zkDocuments": [
//	    {
//	      "proof": bstr,
//	      "documentData": 24(bstr .cbor {
//	        "zkSystemId": tstr,
//	        "docType": tstr,
//	        "timestamp": 0(tstr),          // tdate, no fractional seconds
//	        "issuerSigned": {
//	          <namespace>: [ {"elementIdentifier": tstr, "elementValue": any}, ... ],
//	          ...
//	        },
//	        "deviceSigned": { ... same shape as issuerSigned ... },
//	        "msoX5chain": bstr / [bstr, ...]   // single cert or chain, DER
//	      })
//	    },
//	    ...
//	  ]
//	}
//
// See docs/ZK_PPID_VERIFICATION_PLAN.md for how this plugs into
// verification (zk_verifier.go) - native verification of the PPID
// direction is implemented (opt-in, "zknative" build tag); the non-PPID
// direction remains the documented gap.

import (
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ZkDocumentMdoc is one entry of a DeviceResponse's `zkDocuments` array.
type ZkDocumentMdoc struct {
	// Proof is the opaque zero-knowledge proof bytes (interpreted only by
	// the native ZK system named in DocumentData.ZkSystemID).
	Proof []byte `cbor:"proof"`

	// DocumentData is CBOR tag 24 (encoded CBOR) wrapping a
	// ZkDocumentDataMdoc. Use ParseZkDocumentData to decode it.
	DocumentData EncodedCBORBytes `cbor:"documentData"`
}

// ParseZkDocumentData decodes the tag-24-wrapped ZkDocumentDataMdoc from a
// ZkDocumentMdoc's DocumentData field.
func (z *ZkDocumentMdoc) ParseZkDocumentData() (*ZkDocumentDataMdoc, error) {
	var dd ZkDocumentDataMdoc
	if err := UnwrapEncodedCBOR(z.DocumentData, &dd); err != nil {
		return nil, fmt.Errorf("failed to decode ZkDocumentData: %w", err)
	}
	return &dd, nil
}

// ZkDocumentDataMdoc is "the data the proof will prove" - the disclosed
// claims and metadata bound into a ZK proof, mirroring multipaz's
// ZkDocumentData exactly (field names included, since they are wire names).
type ZkDocumentDataMdoc struct {
	// ZkSystemID identifies which ZK system + circuit variant the wallet
	// used to build Proof (e.g. "longfellow-libzk-v1_8_1_4259_2945").
	// Match this against the DCQL request's meta.zk_system_type entries -
	// see openid4vp.MatchZKSystemType.
	ZkSystemID string `cbor:"zkSystemId"`

	// DocType is the document type of the credential the proof is over
	// (e.g. "org.iso.18013.5.1.mDL").
	DocType string `cbor:"docType"`

	// Timestamp is the RFC 3339 time (tag 0 / tdate, no fractional seconds)
	// the proof was generated at. The native verify call must be given
	// this EXACT string - the ZK proof binds it as one of its public
	// inputs, so recomputing/reformatting it independently would produce a
	// mismatched statement and a verification failure unrelated to the
	// proof's actual validity.
	Timestamp TDate `cbor:"timestamp"`

	// IssuerSigned maps namespace -> disclosed issuer-signed elements.
	// Unlike a plain mdoc's IssuerSignedItem (which carries digestID/random
	// for MSO digest verification), these are just {elementIdentifier,
	// elementValue} pairs - the ZK proof itself attests these came from a
	// validly MSO-signed credential, so per-item digest bytes aren't
	// separately transmitted or needed here.
	IssuerSigned map[string][]ZkSignedItemMdoc `cbor:"issuerSigned"`

	// DeviceSigned maps namespace -> disclosed device-signed elements
	// (e.g. elements asserted by the mdoc app itself, not the issuer).
	// Normally empty - this org's wallets don't currently populate it (see
	// LongfellowZkSystem.kt, which still hard-codes `deviceSigned =
	// emptyMap()`), but the wire format allows it, and a verifier that
	// requested such a claim needs to be able to read it back.
	DeviceSigned map[string][]ZkSignedItemMdoc `cbor:"deviceSigned,omitempty"`

	// MsoX5Chain is the issuer's DS certificate chain: a single bstr (one
	// certificate) or an array of bstr (multiple), each DER-encoded - same
	// convention as a COSE x5chain header (see cose.go). May be absent.
	// Use X5ChainCertificates to get parsed *x509.Certificate values.
	MsoX5Chain any `cbor:"msoX5chain,omitempty"`

	// ClaimSlotDigestIds is Vega-only (r12 circuit revision addendum to
	// docs/ZK_VEGA_DIGESTID_WIRE_EXTENSION.md): the credential's FULL,
	// fixed-shape claim-slot list, in the credential's own document order
	// (VegaProofSystem.MAX_CLAIMS_V1 entries in siros-sdk-kotlin), each
	// entry being that slot's digestID regardless of whether this
	// presentation discloses it. nil for a Longfellow presentation or a
	// pre-r12 Vega artifact. See BuildVegaDisclosedBytes's doc comment for
	// why the verifier needs this to call zk_cred_vega's r12 verify().
	ClaimSlotDigestIds []uint32 `cbor:"claimSlotDigestIds,omitempty"`
}

// ZkSignedItemMdoc is one disclosed element inside a ZkDocumentDataMdoc's
// IssuerSigned/DeviceSigned maps.
type ZkSignedItemMdoc struct {
	ElementIdentifier string `cbor:"elementIdentifier"`
	ElementValue      any    `cbor:"elementValue"`

	// DigestID is the credential's own real ISO 18013-5 IssuerSignedItem
	// digestID for this element - an ADDITIVE, optional extension to
	// multipaz's own zkDocuments wire shape (see
	// docs/ZK_VEGA_DIGESTID_WIRE_EXTENSION.md for the full rationale and
	// its "not yet proposed upstream" status). nil when absent - a
	// Longfellow presentation never needs this (attributes are matched by
	// request-order position, not digestID - see
	// ZkPresentationContext.RequestedClaimIDs's doc comment), so only
	// Vega-producing wallets (siros-sdk-kotlin as of this field's
	// addition - siros-sdk-swift does not yet emit it) populate it.
	DigestID *uint32 `cbor:"digestId,omitempty"`

	// IssuerSignedItemBytes is Vega-only (r12 circuit revision addendum to
	// docs/ZK_VEGA_DIGESTID_WIRE_EXTENSION.md): this element's exact
	// original IssuerSignedItem bytes. nil for a Longfellow presentation
	// or a pre-r12 Vega artifact - see BuildVegaDisclosedBytes's doc
	// comment for why r12 needs it (verify() takes disclosed bytes as an
	// input rather than returning them from the proof).
	IssuerSignedItemBytes []byte `cbor:"issuerSignedItemBytes,omitempty"`
}

// FlattenIssuerSigned converts IssuerSigned into the same
// namespace->identifier->value shape MDocDocumentClaims.Namespaces uses,
// so ZK and non-ZK results can be handled uniformly by callers.
func (dd *ZkDocumentDataMdoc) FlattenIssuerSigned() map[string]map[string]any {
	return flattenZkSignedItems(dd.IssuerSigned)
}

// FlattenDeviceSigned is the DeviceSigned equivalent of FlattenIssuerSigned.
func (dd *ZkDocumentDataMdoc) FlattenDeviceSigned() map[string]map[string]any {
	return flattenZkSignedItems(dd.DeviceSigned)
}

// IssuerSignedItemsByDigestID indexes IssuerSigned by DigestID, across all
// namespaces - the lookup a Vega presentation's verify path needs (see
// docs/ZK_VEGA_DIGESTID_WIRE_EXTENSION.md): the returned proof's disclosed
// claims are matched to a requested identifier via digestID, not position,
// so the verifier needs the wire-declared elementValue for that same
// digestID to compare against.
//
// Returns an error if any disclosed item has no DigestID at all (expected
// only from a pre-digestId-extension wallet, or a non-Vega presentation
// mistakenly routed through this path), or if the same DigestID appears
// more than once (ambiguous - refuses to guess which one was intended,
// mirroring findClaimInNamespaces' identical stance on a duplicate
// elementIdentifier).
func (dd *ZkDocumentDataMdoc) IssuerSignedItemsByDigestID() (map[uint32]ZkSignedItemMdoc, error) {
	out := make(map[uint32]ZkSignedItemMdoc)
	for ns, items := range dd.IssuerSigned {
		for _, item := range items {
			if item.DigestID == nil {
				return nil, fmt.Errorf("issuerSigned item %q (namespace %q) has no digestId - required for Vega claim matching", item.ElementIdentifier, ns)
			}
			if existing, ok := out[*item.DigestID]; ok {
				return nil, fmt.Errorf(
					"digestId %d is disclosed more than once (%q and %q) - ambiguous, refusing to guess which one was intended",
					*item.DigestID, existing.ElementIdentifier, item.ElementIdentifier,
				)
			}
			out[*item.DigestID] = item
		}
	}
	return out, nil
}

func flattenZkSignedItems(m map[string][]ZkSignedItemMdoc) map[string]map[string]any {
	out := make(map[string]map[string]any, len(m))
	for ns, items := range m {
		nsClaims := make(map[string]any, len(items))
		for _, item := range items {
			nsClaims[item.ElementIdentifier] = item.ElementValue
		}
		out[ns] = nsClaims
	}
	return out
}

// X5ChainCertificates parses MsoX5Chain into a slice of certificates
// (leaf-first, matching the COSE x5chain convention used elsewhere in this
// package - see GetCertificateChainFromSign1 in cose.go, whose raw-bytes
// handling this mirrors).
func (dd *ZkDocumentDataMdoc) X5ChainCertificates() ([]*x509.Certificate, error) {
	if dd.MsoX5Chain == nil {
		return nil, fmt.Errorf("msoX5chain is missing")
	}

	var certBytes [][]byte
	switch v := dd.MsoX5Chain.(type) {
	case []byte:
		certBytes = [][]byte{v}
	case [][]byte:
		certBytes = v
	case []any:
		for _, c := range v {
			b, ok := c.([]byte)
			if !ok {
				return nil, fmt.Errorf("invalid certificate entry in msoX5chain")
			}
			certBytes = append(certBytes, b)
		}
	default:
		return nil, fmt.Errorf("invalid msoX5chain type: %T", dd.MsoX5Chain)
	}

	if len(certBytes) == 0 {
		return nil, fmt.Errorf("msoX5chain contains no certificates")
	}

	certs := make([]*x509.Certificate, 0, len(certBytes))
	for _, b := range certBytes {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in msoX5chain: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// PeekIsZkDeviceResponse reports whether data decodes as a DeviceResponse
// (mso_mdoc-shaped CBOR) containing at least one zkDocuments entry - i.e.
// it's a ZK-mdoc ("mso_mdoc_zk") presentation, not a plain "mso_mdoc" one.
// Both formats are wire-compatible base64url CBOR at the byte-sniffing
// level used elsewhere (IsMDocFormat), so distinguishing them requires an
// actual (partial) decode; this is that decode.
//
// Returns (false, err) if data doesn't decode as a DeviceResponse at all -
// callers should treat that as "not a ZK response" and fall through to
// whatever handling they'd otherwise give a decode failure.
func PeekIsZkDeviceResponse(data []byte) (bool, error) {
	// A minimal struct decode (ignoring Documents/DocumentErrors) is
	// cheaper than the full DecodeDeviceResponse - we only need to know
	// whether zkDocuments is present and non-empty.
	var peek struct {
		ZkDocuments []cbor.RawMessage `cbor:"zkDocuments,omitempty"`
	}
	encoder, err := NewCBOREncoder()
	if err != nil {
		return false, err
	}
	if err := encoder.Unmarshal(data, &peek); err != nil {
		return false, fmt.Errorf("failed to decode as DeviceResponse: %w", err)
	}
	return len(peek.ZkDocuments) > 0, nil
}
