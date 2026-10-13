package model

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// Commitment encodings.
const (
	CommitmentEncodingHex    = "hex"
	CommitmentEncodingBase64 = "base64"
)

// CommitmentTarget is one seed-backed claim with everything about WHERE
// and HOW it is written already settled.
type CommitmentTarget struct {
	// Path is the configured claim path, for error messages.
	Path string
	// Element is the key the document is actually keyed by. For mso_mdoc
	// that is the bare element identifier, which is not always what the
	// operator wrote.
	Element string
	// Encoding is how the commitment bytes are written.
	Encoding string
	// Claim is the configuration this came from.
	Claim *CommitmentClaim
}

// ResolveCommitmentTargets settles every seed-backed claim of this
// credential: where it is written, how it is encoded, and whether the
// combination is one the signer will actually emit.
//
// It exists as ONE function, called by both the apigw at startup and the
// issuer at issuance, because the two had grown separate implementations
// of the same resolution and could disagree - at which point startup
// validates one target and the issuer writes another. A disagreement there
// is invisible: the credential is issued, missing a claim or carrying one
// nobody checked.
//
// The schema is a parameter rather than read from this struct, because the
// two callers get it from different places: the apigw loads it at startup
// and passes its own, the issuer receives it inline per request and has
// none stored. Passing it also means nothing here has to copy this struct,
// which carries a mutex.
//
// Everything it reports is deterministic. Nothing iterates a map without
// sorting it first, because the inputs are maps and Go randomises their
// order: a check that passes today and fails tomorrow on the same
// configuration is worse than one that always fails.
func (c *CredentialMetadata) ResolveCommitmentTargets(schema *mdoc.MDDLSchema) ([]CommitmentTarget, error) {
	if c == nil || len(c.Commitments) == 0 {
		return nil, nil
	}

	resolved := make([]CommitmentTarget, 0, len(c.Commitments))
	// Which configured path claimed which element, so that two paths
	// resolving to one element can be named in the error.
	claimedBy := map[string]string{}

	for _, path := range slices.Sorted(maps.Keys(c.Commitments)) {
		claim := c.Commitments[path]
		if claim == nil {
			// Before anything dereferences it. This runs ahead of the
			// struct validation that would otherwise reject it, so a
			// "commitments: {ssc: null}" would panic rather than report.
			return nil, fmt.Errorf("commitment claim %q: empty", path)
		}
		if strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("a commitment claim path is empty")
		}

		element, err := c.resolveElement(schema, path)
		if err != nil {
			return nil, fmt.Errorf("commitment claim %q: %w", path, err)
		}

		encoding, err := resolveEncoding(claim.Encoding, c.Format)
		if err != nil {
			return nil, fmt.Errorf("commitment claim %q: %w", path, err)
		}
		if err := c.checkCarrier(schema, element, encoding); err != nil {
			return nil, fmt.Errorf("commitment claim %q: %w", path, err)
		}

		// Two configured paths may legitimately spell the same element -
		// "ssc" and "<namespace>.ssc" both resolve to "ssc" - and both
		// would pass an existing-value check made against the document as
		// received, because neither has been written yet. The second write
		// would then silently replace the first commitment.
		if other, taken := claimedBy[element]; taken {
			return nil, fmt.Errorf(
				"commitment claims %q and %q both resolve to %q; one would silently overwrite the other",
				other, path, element)
		}
		// In a nested document "a" and "a.b" are mutually exclusive too:
		// the first is written as a string, and writing the second then
		// has to descend through it. Caught here rather than left to
		// issuance, where it is a path conflict that refuses every
		// credential - deterministically, so an operator should be told
		// at startup instead of by the first holder who tries.
		//
		// Not a relation in a flat document, where a dotted element
		// identifier is one key and nothing descends into it.
		if c.Format != openid4vp.FormatMsoMdoc {
			for taken, other := range claimedBy {
				if isNestedUnder(element, taken) || isNestedUnder(taken, element) {
					return nil, fmt.Errorf(
						"commitment claims %q and %q resolve to %q and %q, and one is nested under the other; "+
							"the outer is written as a string, so the inner could never be written at all",
						other, path, taken, element)
				}
			}
		}
		claimedBy[element] = path

		resolved = append(resolved, CommitmentTarget{
			Path:     path,
			Element:  element,
			Encoding: encoding,
			Claim:    claim,
		})
	}

	return resolved, nil
}

// resolveElement maps a configured claim path to the key the document is
// keyed by.
//
// For a format with no mdoc schema the path is the key. For mso_mdoc the
// document is FLAT and keyed by bare element identifier - the signer reads
// doc[elementID] - so a namespace-qualified path has to be normalised, or
// the value is written where nothing reads it and an upstream value at the
// real key goes unnoticed.
//
// Exact matches are resolved in a full pass BEFORE any qualified match is
// considered. The two can collide: a dotted path may be a literal element
// identifier in one namespace and a namespace-qualified spelling in
// another, and resolving them in one pass over a map would pick whichever
// namespace came up first. A path that is still ambiguous after that -
// two namespaces, two different elements - is refused rather than guessed.
func (c *CredentialMetadata) resolveElement(schema *mdoc.MDDLSchema, path string) (string, error) {
	if schema == nil || c.Format != openid4vp.FormatMsoMdoc {
		return path, nil
	}

	for _, namespace := range slices.Sorted(maps.Keys(schema.Claims)) {
		if _, ok := schema.Claims[namespace][path]; ok {
			return path, nil
		}
	}

	var matches []string
	for _, namespace := range slices.Sorted(maps.Keys(schema.Claims)) {
		bare := strings.TrimPrefix(path, namespace+".")
		if bare == path {
			continue
		}
		if _, ok := schema.Claims[namespace][bare]; ok {
			matches = append(matches, bare)
		}
	}
	switch {
	case len(matches) == 1:
		return matches[0], nil
	case len(matches) > 1:
		return "", fmt.Errorf("it is a namespace-qualified spelling of more than one element (%s); write the bare element identifier",
			strings.Join(matches, ", "))
	}

	return "", fmt.Errorf("the schema for doctype %q declares no such element, so the signer would drop it and issue a credential without the commitment",
		schema.DocType)
}

// resolveEncoding decides how the commitment bytes are written.
//
// The default is not a preference, it is what the format's carrier
// accepts: an mso_mdoc bstr element arrives as JSON and is decoded as
// standard base64. Everything else carries the value as the claim itself,
// where hex is what the nym_auth circuits read.
func resolveEncoding(configured, format string) (string, error) {
	switch configured {
	case CommitmentEncodingHex, CommitmentEncodingBase64:
		return configured, nil
	case "":
		if format == openid4vp.FormatMsoMdoc {
			return CommitmentEncodingBase64, nil
		}
		return CommitmentEncodingHex, nil
	default:
		return "", fmt.Errorf("unknown encoding %q", configured)
	}
}

// checkCarrier refuses a target element that cannot carry a commitment.
//
// Every commitment is injected as a JSON STRING, so the element's declared
// value_type decides what mdoc then makes of it. Only two can hold one:
//
//   - bstr, which mdoc decodes as standard base64. A 64-character SHA-256
//     hex string is ITSELF valid base64, so configuring hex here does not
//     fail - it decodes to 48 bytes of nothing and is signed as the
//     commitment, and a 48-byte bstr is perfectly well-formed. Base64 only.
//   - tstr, which carries the string as written.
//
// Everything else is refused at startup rather than at issuance. int and
// uint fail the conversion - after a status list entry has been allocated
// and never handed back - and bool, array and map do not fail at all:
// convertElementValue passes an unrecognised value_type through unchanged,
// so the commitment would be signed as a CBOR text string where the schema
// promises something else, and only a verifier would ever find out.
func (c *CredentialMetadata) checkCarrier(schema *mdoc.MDDLSchema, element, encoding string) error {
	if schema == nil || c.Format != openid4vp.FormatMsoMdoc {
		return nil
	}
	for _, namespace := range slices.Sorted(maps.Keys(schema.Claims)) {
		meta, ok := schema.Claims[namespace][element]
		if !ok {
			continue
		}
		switch meta.ValueType {
		case "bstr":
			if encoding != CommitmentEncodingBase64 {
				return fmt.Errorf("the schema declares it as bstr, which mdoc decodes as base64, so encoding %q would sign the decoded %[1]s string instead of the commitment", encoding)
			}
			return nil
		case "tstr":
			return nil
		default:
			return fmt.Errorf("the schema declares it as %q, which cannot carry a commitment: it is injected as a JSON string, and only bstr and tstr elements accept one",
				meta.ValueType)
		}
	}
	return nil
}

// isNestedUnder reports whether child is written inside parent in a
// nested document - "a.b" under "a", but not "ab" under "a".
func isNestedUnder(child, parent string) bool {
	return strings.HasPrefix(child, parent+".")
}
