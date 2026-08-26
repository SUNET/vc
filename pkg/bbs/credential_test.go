package bbs

import (
	"encoding/json"
	"strings"
	"testing"
)

// Map iteration in Go is randomised, so a mapping that derived order from
// iteration would produce a different credential on every call — and the
// resulting proof would fail to verify with nothing to point at. This is
// the single most important property of the layout.
func TestCanonicalMessagesIsDeterministic(t *testing.T) {
	doc := []byte(`{"family_name":"Andersson","given_name":"Ada","address":{"city":"Uppsala","zip":"75105"},"tags":["a","b"]}`)

	first, firstPtrs, err := CanonicalMessages(doc)
	if err != nil {
		t.Fatalf("CanonicalMessages: %v", err)
	}
	for i := 0; i < 50; i++ {
		got, gotPtrs, err := CanonicalMessages(doc)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if len(got) != len(first) {
			t.Fatalf("iteration %d: message count changed", i)
		}
		for j := range got {
			if string(got[j]) != string(first[j]) {
				t.Fatalf("iteration %d, message %d: %q != %q", i, j, got[j], first[j])
			}
			if gotPtrs[j] != firstPtrs[j] {
				t.Fatalf("iteration %d: pointer %d changed", i, j)
			}
		}
	}
}

// Every message carries its own pointer. Without that, a holder could
// present the value of one claim as though it were another — the
// signature covers the value either way.
func TestMessagesBindTheClaimName(t *testing.T) {
	a, _, err := CanonicalMessages([]byte(`{"role":"admin","name":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := CanonicalMessages([]byte(`{"role":"x","name":"admin"}`))
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if string(a[i]) == string(b[i]) {
			t.Fatalf("swapping two claim values produced an identical message at %d: %q", i, a[i])
		}
	}
}

// Round-tripping numbers through float64 would rewrite 1.0 as 1 and lose
// precision on large integers, silently changing the signed bytes for a
// document that never changed.
func TestNumbersKeepTheirLiteralForm(t *testing.T) {
	for _, tc := range []struct{ doc, want string }{
		{`{"n":1.0}`, `1.0`},
		{`{"n":1}`, `1`},
		{`{"n":10000000000000000000000}`, `10000000000000000000000`},
		{`{"n":1.7976931348623157e+308}`, `1.7976931348623157e+308`},
	} {
		msgs, _, err := CanonicalMessages([]byte(tc.doc))
		if err != nil {
			t.Fatalf("%s: %v", tc.doc, err)
		}
		if !strings.Contains(string(msgs[0]), tc.want) {
			t.Fatalf("%s: message %q lost the literal %q", tc.doc, msgs[0], tc.want)
		}
	}
}

// A claim named "a/b" must not collide with a nested "a" containing "b" —
// RFC 6901 escaping exists for exactly this.
func TestPointerEscapingPreventsCollisions(t *testing.T) {
	flat, flatPtrs, err := CanonicalMessages([]byte(`{"a/b":1}`))
	if err != nil {
		t.Fatal(err)
	}
	nested, nestedPtrs, err := CanonicalMessages([]byte(`{"a":{"b":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(flat[0]) == string(nested[0]) {
		t.Fatalf("%q and %q produced the same message", flatPtrs[0], nestedPtrs[0])
	}
	if flatPtrs[0] != "/a~1b" {
		t.Fatalf("expected escaped pointer /a~1b, got %q", flatPtrs[0])
	}
}

// Dropping empty containers would make {"a":{}} and {} sign identically,
// so a holder could claim a credential said nothing about "a".
func TestEmptyContainersAreSigned(t *testing.T) {
	msgs, ptrs, err := CanonicalMessages([]byte(`{"a":{},"b":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected empty object and array to each be a message, got %d: %v", len(msgs), ptrs)
	}
}

func TestCanonicalMessagesRejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"not JSON", `not json`},
		{"not an object", `["a"]`},
		{"empty object", `{}`},
		{"trailing content", `{"a":1} {"b":2}`},
		{"empty input", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := CanonicalMessages([]byte(tc.doc)); err == nil {
				t.Fatalf("accepted %q", tc.doc)
			}
		})
	}
}

// The count comes from caller-supplied claims, so it must be bounded:
// otherwise a caller dictates how much work the issuer does.
func TestCanonicalMessagesBoundsMessageCount(t *testing.T) {
	m := map[string]int{}
	for i := 0; i <= MaxMessages; i++ {
		m[string(rune('a'+i%26))+string(rune(i))] = i
	}
	doc, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CanonicalMessages(doc); err == nil {
		t.Fatal("accepted a document over the message limit")
	}
}

// An issuer must never sign without a commitment: the commitment is what
// carries the holder's key binding keys and the proof it holds them.
func TestIssueRequiresACommitment(t *testing.T) {
	_, err := Issue(Native(), IssueParams{DocumentData: []byte(`{"a":1}`)})
	if err == nil {
		t.Fatal("issued a credential with no commitment")
	}
	if !strings.Contains(err.Error(), "commitment") {
		t.Fatalf("error should name the missing commitment, got %v", err)
	}
}

// Claims are canonicalised before the signer is reached, so a malformed
// document fails without consuming the issuer key at all.
func TestIssueRejectsBadClaimsBeforeSigning(t *testing.T) {
	_, err := Issue(Native(), IssueParams{
		Commitment:   []byte{1, 2, 3},
		DocumentData: []byte(`not json`),
	})
	if err == nil {
		t.Fatal("issued a credential from malformed claims")
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Fatalf("want a JSON error, got %v", err)
	}
}

func TestDecodeCommitment(t *testing.T) {
	if _, err := DecodeCommitment(""); err == nil {
		t.Fatal("accepted an empty commitment")
	}
	if _, err := DecodeCommitment("!!!not base64!!!"); err == nil {
		t.Fatal("accepted invalid base64url")
	}
	// Padded and unpadded must both work: wallets differ.
	for _, s := range []string{"AQID", "AQID=="} {
		got, err := DecodeCommitment(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if string(got) != "\x01\x02\x03" {
			t.Fatalf("%q decoded to %x", s, got)
		}
	}
}
