package schemameta

import (
	"fmt"
	"strings"
)

// SchemaMeta is one credential's entry in a TS11 /api/v1/schemas.json
// response - a different wire shape from Index/Entry (the
// .well-known/vctm-registry.json discovery format): it identifies formats
// by media-type-like FormatIdentifier values ("dc+sd-jwt", "mso_mdoc", ...)
// rather than Entry.Formats' file-extension-like keys ("vctm", "mdoc"), and
// carries no "vct" field of its own - the authoritative identifier lives
// inside each fetched document.
type SchemaMeta struct {
	ID                 string      `json:"id"`
	Version            string      `json:"version"`
	AttestationLoS     string      `json:"attestationLoS"`
	BindingType        string      `json:"bindingType"`
	SupportedFormats   []string    `json:"supportedFormats"`
	SchemaURIs         []SchemaURI `json:"schemaURIs"`
	RulebookURI        string      `json:"rulebookURI"`
	TrustedAuthorities []string    `json:"trustedAuthorities,omitempty"`
}

// SchemaURI is one format's document location within a SchemaMeta.
type SchemaURI struct {
	FormatIdentifier string `json:"formatIdentifier"`
	URI              string `json:"uri"`
}

// TS11SchemasPage is one page of a TS11 /api/v1/schemas.json response.
// It supports both the current wire shape ("data"/"total"/"limit"/"offset")
// and the legacy one ("schemas"/"next"/"page"/"pageSize").
type TS11SchemasPage struct {
	Data     []SchemaMeta `json:"data"`
	Schemas  []SchemaMeta `json:"schemas"`
	Total    int          `json:"total,omitempty"`
	Limit    int          `json:"limit,omitempty"`
	Offset   int          `json:"offset,omitempty"`
	Page     int          `json:"page,omitempty"`
	PageSize int          `json:"pageSize,omitempty"`
	Next     string       `json:"next,omitempty"`
}

// Entries returns whichever schema array is populated (Data takes
// precedence over the legacy Schemas key).
func (p *TS11SchemasPage) Entries() []SchemaMeta {
	if len(p.Data) > 0 {
		return p.Data
	}
	return p.Schemas
}

// HasMorePages reports whether another page follows this one.
func (p *TS11SchemasPage) HasMorePages() bool {
	if p.Next != "" {
		return true
	}
	return p.Limit > 0 && p.Offset+len(p.Entries()) < p.Total
}

// NextPageURL returns the URL for the next page, given the URL this page
// was fetched from. For the legacy shape it's the "next" field verbatim;
// for the current shape it's baseURL with its offset advanced.
func (p *TS11SchemasPage) NextPageURL(baseURL string) string {
	if p.Next != "" {
		return p.Next
	}
	nextOffset := p.Offset + len(p.Entries())
	clean := baseURL
	sep := "?"
	if idx := strings.Index(clean, "offset="); idx > 0 {
		end := strings.IndexByte(clean[idx:], '&')
		if end == -1 {
			clean = clean[:idx-1]
		} else {
			clean = clean[:idx] + clean[idx+end+1:]
		}
	}
	if strings.Contains(clean, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%soffset=%d", clean, sep, nextOffset)
}
