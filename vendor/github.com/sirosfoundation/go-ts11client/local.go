package ts11client

import (
	"context"
	"fmt"

	"github.com/sirosfoundation/go-ts11client/schemameta"
)

// Compile-time check: LocalSource satisfies Client directly (its method
// set already matches), so it can be used standalone wherever a Client is
// expected, not just composed inside MultiRegistryClient.
var _ Client = (*LocalSource)(nil)

// LocalEntry is one statically-configured metadata document - the
// caller's existing "vendored local file" behavior, expressed as data
// rather than a file path so callers can load it however they already do
// (embed, disk, config). Exactly one of VCT/Doctype should be set,
// matching which format Data holds.
type LocalEntry struct {
	VCT     string // set for an SD-JWT VC Type Metadata document
	Doctype string // set for an mdoc MDDL metadata document
	Data    []byte
}

// LocalSource is a fixed set of metadata documents that never expire and
// are never re-fetched - it exists so a deployment's existing local-file
// configuration keeps working unchanged when a MultiRegistryClient is
// introduced alongside it: a LocalSource entry behaves as if permanently
// present in the cache, and is always checked (and always wins) before
// any registry is consulted.
type LocalSource struct {
	byVCT     map[string][]byte
	byDoctype map[string][]byte
}

// NewLocalSource builds a LocalSource from a fixed list of entries.
func NewLocalSource(entries ...LocalEntry) (*LocalSource, error) {
	l := &LocalSource{
		byVCT:     make(map[string][]byte, len(entries)),
		byDoctype: make(map[string][]byte, len(entries)),
	}
	for _, e := range entries {
		switch {
		case e.VCT != "" && e.Doctype != "":
			return nil, fmt.Errorf("ts11client: local entry cannot set both VCT and Doctype")
		case e.VCT != "":
			l.byVCT[e.VCT] = e.Data
		case e.Doctype != "":
			l.byDoctype[e.Doctype] = e.Data
		default:
			return nil, fmt.Errorf("ts11client: local entry must set VCT or Doctype")
		}
	}
	return l, nil
}

// ResolveVCT returns the locally-configured document for vct, if any.
func (l *LocalSource) ResolveVCT(ctx context.Context, vct string) (*Resolved, error) {
	if l == nil {
		return nil, fmt.Errorf("%w: vct=%q", ErrNotFound, vct)
	}
	data, ok := l.byVCT[vct]
	if !ok {
		return nil, fmt.Errorf("%w: vct=%q", ErrNotFound, vct)
	}
	return &Resolved{
		Entry:  schemameta.Entry{VCT: vct},
		Format: schemameta.FormatVCTM,
		Data:   data,
		Source: "local",
	}, nil
}

// ResolveDoctype returns the locally-configured document for doctype, if any.
func (l *LocalSource) ResolveDoctype(ctx context.Context, doctype string) (*Resolved, error) {
	if l == nil {
		return nil, fmt.Errorf("%w: doctype=%q", ErrNotFound, doctype)
	}
	data, ok := l.byDoctype[doctype]
	if !ok {
		return nil, fmt.Errorf("%w: doctype=%q", ErrNotFound, doctype)
	}
	return &Resolved{
		Entry:  schemameta.Entry{},
		Format: schemameta.FormatMDOC,
		Data:   data,
		Source: "local",
	}, nil
}
