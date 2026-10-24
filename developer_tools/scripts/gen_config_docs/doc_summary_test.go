package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The first sentence ends where go/doc's Synopsis ends it, and "e.g." ends
// no sentence.
func TestDocSummary(t *testing.T) {
	for name, tc := range map[string]struct {
		doc     string
		summary string
		rest    []string
	}{
		"a wrapped sentence":         {"A wraps over\ntwo lines.\nNext.", "A wraps over two lines.", []string{"Next."}},
		"two sentences on one line":  {"A is x. B is y.\n\nC.", "A is x.", []string{"B is y.", "", "C."}},
		"an abbreviation":            {"A, e.g. b, is x.\nNext.", "A, e.g. b, is x.", []string{"Next."}},
		"an initial":                 {"Set by J. Smith.\nNext.", "Set by J. Smith.", []string{"Next."}},
		"a paragraph without period": {"A is x\nB is y\n\nC.", "A is x B is y", []string{"", "C."}},
		"a fence after the summary":  {"A is x\n```\ncode\n```", "A is x", []string{"```", "code", "```"}},
	} {
		summary, rest := docSummary(tc.doc)
		assert.Equal(t, tc.summary, summary, name)
		assert.Equal(t, tc.rest, rest, name)
	}
}
