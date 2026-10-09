package main

import (
	"strings"
	"testing"
)

// A Go doc comment wraps at around 72 columns, so the opening SENTENCE is
// routinely longer than the opening LINE. Splitting on the line handed half
// a sentence to the summary and the other half to the section body, which
// then began mid-clause - ZkKeyCacheConfig rendered as "verifier keys (see
// pkg/mdoc's vegaKeyStore)...".
func TestSplitLeadParagraph(t *testing.T) {
	for name, tc := range map[string]struct {
		doc      string
		wantLead string
		wantRest string
	}{
		"wrapped first sentence": {
			doc:      "ZkKeyCacheConfig configures the process-local store of decompressed Vega\nverifier keys (see pkg/mdoc's vegaKeyStore). Only consulted by builds\nwith the \"zknative\" Go build tag.\n\nA key is ~100MB.",
			wantLead: "ZkKeyCacheConfig configures the process-local store of decompressed Vega verifier keys (see pkg/mdoc's vegaKeyStore). Only consulted by builds with the \"zknative\" Go build tag.",
			wantRest: "A key is ~100MB.",
		},
		"single line": {
			doc:      "Thing does one thing.",
			wantLead: "Thing does one thing.",
			wantRest: "",
		},
		"fence ends the lead": {
			doc:      "Thing does one thing.\n```yaml\nkey: value\n```",
			wantLead: "Thing does one thing.",
			wantRest: "```yaml\nkey: value\n```",
		},
	} {
		t.Run(name, func(t *testing.T) {
			lead, rest := splitLeadParagraph(tc.doc)
			if lead != tc.wantLead {
				t.Errorf("lead  = %q\nwant  = %q", lead, tc.wantLead)
			}
			if got := strings.TrimSpace(strings.Join(rest, "\n")); got != tc.wantRest {
				t.Errorf("rest  = %q\nwant  = %q", got, tc.wantRest)
			}
		})
	}
}

// The section body must carry the whole opening sentence, not the tail of
// it and not nothing at all. Its callers have nowhere else that shows it:
// the parent table renders the FIELD's comment, which is a different
// sentence about a different thing.
func TestStructDescriptionExtraKeepsTheLeadSentence(t *testing.T) {
	def := &StructDef{
		Name: "ZkKeyCacheConfig",
		Doc:  "ZkKeyCacheConfig configures the process-local store of decompressed Vega\nverifier keys (see pkg/mdoc's vegaKeyStore).\n\nA key is ~100MB.",
	}

	got := structDescriptionExtra(def)

	if !strings.HasPrefix(got, "The process-local store of decompressed Vega verifier keys") {
		t.Errorf("the body does not open with the full lead sentence:\n%s", got)
	}
	if strings.HasPrefix(got, "verifier keys") {
		t.Error("the body opens mid-sentence, which is the bug this guards")
	}
	if !strings.Contains(got, "A key is ~100MB.") {
		t.Errorf("the body lost the paragraphs after the lead:\n%s", got)
	}
}
