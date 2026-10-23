package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/nymauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedCommitmentsDoc(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "issuer", "SEED_COMMITMENTS.md"))
	require.NoError(t, err)
	return string(raw)
}

// Every -verifier-id the document hands an operator has to be one this
// tool accepts.
//
// This is the failure the document actually shipped: it told the reader
// to pass the BARE verifier_id, which rulebook v0.4 refuses. An operator
// following the page could not run the tool at all - and the earlier
// version of that same page, which the bare value came from, would have
// had them compute a pseudonym no Verifier reports and conclude a
// subject was innocent.
func TestEveryVerifierIDTheDocumentSuggestsIsOneTheToolAccepts(t *testing.T) {
	flagExample := regexp.MustCompile(`-verifier-id\s+(\S+)`)

	matches := flagExample.FindAllStringSubmatch(seedCommitmentsDoc(t), -1)
	require.NotEmpty(t, matches, "the document no longer shows a -verifier-id example; this guard is reading the wrong file")

	for _, match := range matches {
		value := match[1]
		t.Run(value, func(t *testing.T) {
			assert.NoErrorf(t, nymauth.CheckVerifierID(value),
				"the document tells an operator to pass %q, which this tool refuses", value)
		})
	}
}

// The document publishes two worked digests, one of them as the value to
// use. A digest is not something a reader can check by eye, so a wrong
// one is believed - and this pair was inverted once already, by v0.4.
func TestTheDocumentsWorkedDigestsAreReal(t *testing.T) {
	doc := seedCommitmentsDoc(t)

	for _, tc := range []struct{ input, prefix string }{
		{"x509_san_dns:verifier.example", "6eae85a0"},
		{"verifier.example", "be6a6400"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			sum := sha256.Sum256([]byte(tc.input))
			full := hex.EncodeToString(sum[:])
			require.Truef(t, strings.HasPrefix(full, tc.prefix),
				"this guard's own expectation is stale: SHA256(%q) starts %s, not %s", tc.input, full[:8], tc.prefix)
			assert.Containsf(t, doc, tc.prefix,
				"the document no longer shows the digest of %q", tc.input)
		})
	}

	// Which of the two is the one to USE. Both digests appear on the
	// page, so finding one proves nothing about which it recommends.
	assert.Contains(t, doc, `SHA256("x509_san_dns:verifier.example") = 6eae85a0…6bab   (MUST)`,
		"the document must mark the PREFIXED form as the one that is hashed")
	assert.NotContains(t, doc, `SHA256("verifier.example")              = be6a6400…4a41   (MUST)`,
		"the document marks the bare DNS name as the value to hash, which v0.4 inverted")
}
