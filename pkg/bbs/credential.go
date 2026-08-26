package bbs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// LayoutVersion identifies the claim-to-message mapping below.
//
// A BBS signature covers an *ordered list of messages*. Issuer and holder
// must derive byte-identical lists from the same claims or nothing
// verifies — and the failure is silent, appearing only as a proof that
// will not verify, with nothing to point at. So the mapping is pinned, and
// pinned visibly.
//
// It is also frozen per credential: messages cannot be added, removed or
// reordered after issuance without re-issuing. Carrying the version with
// the credential is what turns a future change into a detectable migration
// ("this one is v0, we now issue v1, re-issue it") rather than a
// verification failure that looks like a bug.
const LayoutVersion = "siros-bbs-layout-v0"

// MaxMessages bounds how many messages one credential may carry.
//
// Not a protocol limit — a guard. Message count drives generator
// derivation and proof size, and the count comes from caller-supplied
// claims, so an unbounded document would let a caller dictate how much
// work the issuer does.
const MaxMessages = 512

// Credential is what an issuer produces for a holder.
//
// It is deliberately not a serialized container. The standards-track
// container is JWP (draft-bormann-jwp-modular-bbs), which is not
// implemented here yet; these are the values a JWP would carry, and the
// values the holder needs to produce a presentation regardless of framing.
type Credential struct {
	// Signature is the blind BBS signature over Messages plus the
	// holder's committed messages.
	Signature []byte `json:"signature"`

	// Messages are the issuer-known messages, in the exact order they
	// were signed. Order is part of what the signature covers.
	Messages [][]byte `json:"messages"`

	// Pointers names the claim each message came from, in the same order,
	// so a holder can map "disclose the birth date" onto a message index
	// without re-deriving the layout.
	Pointers []string `json:"pointers"`

	// Layout is the mapping version these messages were derived under.
	Layout string `json:"layout"`

	// Suite is the key binding construction the credential is bound to.
	Suite Suite `json:"suite"`
}

// CanonicalMessages flattens a JSON claims document into the ordered
// message list a BBS signature covers.
//
// Each leaf becomes one message, encoded as the canonical JSON array
// `["<RFC 6901 pointer>",<value>]`. Two properties matter and are the
// reason this is not just `range` over a map:
//
//   - **Total order.** Messages are sorted by pointer. Go map iteration is
//     deliberately randomised, so deriving order from iteration would
//     produce a different credential on every call.
//   - **Stable number encoding.** Numbers are decoded as json.Number and
//     re-emitted as their original literal. Round-tripping through float64
//     would rewrite `1.0` as `1` and lose precision on large integers,
//     changing the message bytes for a document that never changed.
//
// Binding the pointer into the message, rather than signing bare values,
// is what stops a holder presenting the value of one claim as though it
// were another.
func CanonicalMessages(documentData []byte) ([][]byte, []string, error) {
	dec := json.NewDecoder(bytes.NewReader(documentData))
	dec.UseNumber()

	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, nil, fmt.Errorf("bbs: claims are not valid JSON: %w", err)
	}
	if dec.More() {
		return nil, nil, fmt.Errorf("bbs: claims contain trailing content after the JSON document")
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("bbs: claims must be a JSON object, got %T", root)
	}
	// The empty-container rule below deliberately treats `{}` as a leaf, so
	// that `{"a":{}}` and `{}` do not sign identically. At the ROOT that
	// rule would turn a claimless document into a one-message credential
	// instead of an error, so the root is checked separately. Found by the
	// test for this, not by inspection.
	if len(obj) == 0 {
		return nil, nil, fmt.Errorf("bbs: claims contain no values to sign")
	}

	leaves := map[string]any{}
	flatten("", root, leaves)

	pointers := make([]string, 0, len(leaves))
	for p := range leaves {
		pointers = append(pointers, p)
	}
	sort.Strings(pointers)

	if len(pointers) == 0 {
		return nil, nil, fmt.Errorf("bbs: claims contain no values to sign")
	}
	if len(pointers) > MaxMessages {
		return nil, nil, fmt.Errorf("bbs: claims contain %d values, over the %d limit", len(pointers), MaxMessages)
	}

	messages := make([][]byte, 0, len(pointers))
	for _, p := range pointers {
		msg, err := json.Marshal([]any{p, leaves[p]})
		if err != nil {
			return nil, nil, fmt.Errorf("bbs: encoding claim %q: %w", p, err)
		}
		messages = append(messages, msg)
	}
	return messages, pointers, nil
}

// flatten walks a decoded JSON value, recording each leaf against its
// RFC 6901 pointer. Empty objects and arrays are leaves in their own
// right: dropping them would make `{"a":{}}` and `{}` sign identically.
func flatten(prefix string, v any, out map[string]any) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			out[pointerOr(prefix)] = t
			return
		}
		for k, child := range t {
			flatten(prefix+"/"+escapePointer(k), child, out)
		}
	case []any:
		if len(t) == 0 {
			out[pointerOr(prefix)] = t
			return
		}
		for i, child := range t {
			flatten(fmt.Sprintf("%s/%d", prefix, i), child, out)
		}
	default:
		out[pointerOr(prefix)] = v
	}
}

func pointerOr(prefix string) string {
	if prefix == "" {
		return "/"
	}
	return prefix
}

// escapePointer applies RFC 6901's escaping, without which a claim named
// "a/b" would be indistinguishable from a nested "a" containing "b".
func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// IssueParams is everything an issuer needs to produce a BBS credential.
type IssueParams struct {
	// Suite is the key binding construction. Must match what the holder
	// used to build Commitment; a mismatch changes the domain separation
	// and the result verifies against nothing.
	Suite Suite

	// SecretKey and PublicKey are the issuer's BBS key pair. Note this
	// cannot be a pki.Signer or a PKCS#11 key: a BBS secret key is a
	// BLS12-381 scalar consumed inside the signing algebra, not something
	// that signs a digest, and mainstream HSMs do not implement the curve.
	SecretKey []byte
	PublicKey []byte

	// Header is bound into the signature and must be reproduced verbatim
	// at presentation time.
	Header []byte

	// Commitment is the holder's `commitment_with_proof`, carrying the
	// messages the issuer never sees and the key binding public keys,
	// together with proof the holder actually holds those keys.
	Commitment []byte

	// DocumentData is the issuer's own claims, as a JSON object.
	DocumentData []byte
}

// Issue verifies the holder's commitment and blind-signs it together with
// the issuer's claims.
//
// The commitment is verified before anything is signed — including each
// authenticator's proof of possession of its key binding key. That check
// is what stops a holder binding a credential to a key it does not
// control, so it is not optional and not deferred to presentation time.
func Issue(signer BlindSigner, p IssueParams) (*Credential, error) {
	if len(p.Commitment) == 0 {
		return nil, fmt.Errorf("bbs: commitment is required")
	}
	messages, pointers, err := CanonicalMessages(p.DocumentData)
	if err != nil {
		return nil, err
	}

	signature, err := signer.BlindSign(p.Suite, p.SecretKey, p.PublicKey, p.Commitment, p.Header, messages)
	if err != nil {
		return nil, err
	}

	return &Credential{
		Signature: signature,
		Messages:  messages,
		Pointers:  pointers,
		Layout:    LayoutVersion,
		Suite:     p.Suite,
	}, nil
}

// DecodeCommitment decodes a base64url-encoded `commitment_with_proof` as
// it arrives on the wire.
func DecodeCommitment(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("bbs: commitment is not valid base64url: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("bbs: commitment is empty")
	}
	return b, nil
}
