package ts11client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sirosfoundation/go-ts11client/schemameta"
)

// TS11Document is one resolved (schema, format) document from a paginated
// TS11 /api/v1/schemas.json endpoint - a schema commonly declares more than
// one format (e.g. both "dc+sd-jwt" and "mso_mdoc") for the same logical
// credential, so one SchemaMeta can produce several TS11Documents.
type TS11Document struct {
	Schema           schemameta.SchemaMeta
	FormatIdentifier string
	URI              string
	Data             []byte
}

// SkipReason categorizes why FetchTS11Schemas skipped an item, so callers
// can log/monitor each distinctly instead of treating every skip as an
// identical generic failure.
type SkipReason int

const (
	// SkipReasonNoSchemaURIs means a schema declared no schemaURIs at
	// all, so no document fetch was even attempted.
	SkipReasonNoSchemaURIs SkipReason = iota
	// SkipReasonFetchFailed means a specific format document's fetch
	// (or read) failed.
	SkipReasonFetchFailed
)

// SkippedDocument records one schema/format document that couldn't be
// fetched or was otherwise skipped, so callers can still log or monitor
// individual failures even though FetchTS11Schemas itself treats them as
// non-fatal.
type SkippedDocument struct {
	Reason           SkipReason
	SchemaID         string
	FormatIdentifier string
	URI              string
	Err              error
}

// FetchTS11Schemas fetches every page of a TS11 /api/v1/schemas.json
// endpoint (following pagination to exhaustion) and every schema's
// declared format documents.
//
// This is a stateless bulk operation, unlike ResolveVCT/ResolveDoctype: it
// has no cache and no local-override layer, since callers that need a
// poll-and-store model of their own (rather than per-key lazy resolution)
// already have their own storage/caching for exactly that - this just does
// the network fetch/parse/paginate mechanics for them.
//
// A single schema or format document that fails to fetch or parse is
// skipped, not fatal - matching how a partial catalog is still useful -
// but is still reported via the returned skipped slice so callers can log
// or monitor individual failures. Only a failure fetching or parsing the
// first page fails the whole call.
func FetchTS11Schemas(ctx context.Context, httpClient *http.Client, endpointURL string) ([]TS11Document, []SkippedDocument, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	body, err := fetchURL(ctx, httpClient, endpointURL)
	if err != nil {
		return nil, nil, fmt.Errorf("ts11client: fetch schemas page from %s: %w", endpointURL, err)
	}
	return FetchTS11SchemasFromFirstPage(ctx, httpClient, endpointURL, body)
}

// FetchTS11SchemasFromFirstPage is FetchTS11Schemas for callers that
// already fetched endpointURL's first-page body themselves - e.g. as part
// of their own response-format auto-detection, before knowing this was a
// TS11 schemas.json response. It reuses firstPageBody instead of fetching
// endpointURL a second time, and only fetches subsequent pages (if any).
func FetchTS11SchemasFromFirstPage(ctx context.Context, httpClient *http.Client, endpointURL string, firstPageBody []byte) ([]TS11Document, []SkippedDocument, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	var docs []TS11Document
	var skipped []SkippedDocument
	currentURL := endpointURL
	body := firstPageBody
	first := true

	for {
		var page schemameta.TS11SchemasPage
		if err := json.Unmarshal(body, &page); err != nil {
			if first {
				return nil, nil, fmt.Errorf("ts11client: decode schemas page from %s: %w", currentURL, err)
			}
			break
		}
		first = false

		for _, schema := range page.Entries() {
			if len(schema.SchemaURIs) == 0 {
				skipped = append(skipped, SkippedDocument{
					Reason:   SkipReasonNoSchemaURIs,
					SchemaID: schema.ID,
					Err:      fmt.Errorf("schema has no schemaURIs"),
				})
				continue
			}
			for _, su := range schema.SchemaURIs {
				data, err := fetchURL(ctx, httpClient, su.URI)
				if err != nil {
					skipped = append(skipped, SkippedDocument{
						Reason:           SkipReasonFetchFailed,
						SchemaID:         schema.ID,
						FormatIdentifier: su.FormatIdentifier,
						URI:              su.URI,
						Err:              err,
					})
					continue
				}
				docs = append(docs, TS11Document{
					Schema:           schema,
					FormatIdentifier: su.FormatIdentifier,
					URI:              su.URI,
					Data:             data,
				})
			}
		}

		if !page.HasMorePages() {
			break
		}
		currentURL = page.NextPageURL(currentURL)
		nextBody, err := fetchURL(ctx, httpClient, currentURL)
		if err != nil {
			break
		}
		body = nextBody
	}

	return docs, skipped, nil
}

// fetchURL performs a simple GET and returns the response body.
func fetchURL(ctx context.Context, httpClient *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}
