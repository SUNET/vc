package openid4vp

import "strings"

// compactTerm returns the compact term an expanded type IRI stands for: what
// follows its last '#', or, without a fragment, its last path segment. An
// input with neither (or one that is not absolute) is returned unchanged, so a
// value that is already a compact term passes through.
func compactTerm(iri string) string {
	if i := strings.LastIndex(iri, "#"); i >= 0 {
		if i == len(iri)-1 {
			return iri // an empty fragment names no term
		}
		return iri[i+1:]
	}
	_, rest, ok := strings.Cut(iri, "://")
	if !ok {
		return iri
	}
	// The query is not part of the path. Left on, it either rides along on the term
	// ("Diploma?version=1") or supplies the last slash itself ("?next=/Other" yielding
	// "Other"), and a wallet matching on either finds no credential.
	rest, _, _ = strings.Cut(rest, "?")
	// Only the path counts: a slash in the scheme separator or a bare host is not a segment.
	rest = strings.TrimRight(rest, "/")
	if i := strings.LastIndex(rest, "/"); i >= 0 && i < len(rest)-1 {
		return rest[i+1:]
	}
	return iri
}

// WithCompactW3CTypeValues returns a copy of the query in which every W3C
// credential query names its type_values by compact term instead of expanded
// IRI. The receiver is not modified: the expanded form is what the response
// check matches, so only the copy that goes to the wallet may be compacted.
//
// Credential queries of other formats are shared with the receiver, not
// copied. A nil receiver returns nil.
func (q *DCQL) WithCompactW3CTypeValues() *DCQL {
	if q == nil {
		return nil
	}
	out := *q
	out.Credentials = make([]CredentialQuery, len(q.Credentials))
	copy(out.Credentials, q.Credentials)
	for i := range out.Credentials {
		cq := &out.Credentials[i]
		if !IsW3CVCFormatIdentifier(cq.Format) || len(cq.Meta.TypeValues) == 0 {
			continue
		}
		compact := make([][]string, len(cq.Meta.TypeValues))
		for j, alternative := range cq.Meta.TypeValues {
			compact[j] = make([]string, len(alternative))
			for k, t := range alternative {
				compact[j][k] = compactTerm(t)
			}
		}
		cq.Meta.TypeValues = compact
	}
	return &out
}
