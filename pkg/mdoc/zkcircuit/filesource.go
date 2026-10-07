package zkcircuit

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// A Sources entry may be a file:// URL naming a VENDORED MIRROR - a
// directory laid out exactly like the REST service
// (v1/manifest.json, v1/circuits/<id>.json, and whatever relative
// artifact paths the descriptors carry), as written by
// developer_tools/scripts/vendor_zk_circuits.
//
// This is the same catalog reached a different way, which is precisely
// what a Sources entry already means, so a vendored mirror needs no second
// code path: the client builds the same v1/... URLs and reads them off
// disk instead of off the network. That matters for two deployments. An
// issuer only ever needs the few-KB descriptors, and making it depend on
// a remote service to mint a credential buys nothing. And an air-gapped
// or reproducible deployment wants the exact circuit bytes it tested
// against, not whatever the catalog serves on the day.
//
// Hash verification is unchanged and still applies: DownloadArtifact
// checks SHA-256 against the descriptor whatever the source, so a vendored
// tree that has been edited underneath fails the same way a tampered
// download does.

// isFileURL reports whether rawURL is a file:// URL.
func isFileURL(rawURL string) bool {
	return strings.HasPrefix(rawURL, "file://")
}

// fetchFile reads a file:// URL, refusing to read more than maxBytes.
//
// The cap is the same one the HTTP path enforces and for the same reason:
// a vendored mirror is operator-supplied, but "operator-supplied" is not
// "known-good" - it was downloaded from the catalog at some point, and a
// decompression-bomb-sized descriptor should bound out here rather than in
// the allocator.
func fetchFile(rawURL string, maxBytes int64) ([]byte, error) {
	path, err := filePathFromURL(rawURL)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open vendored circuit file %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat vendored circuit file %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("vendored circuit path %s is a directory, not a file", path)
	}

	// maxBytes+1 so an oversized file is reported as oversized rather than
	// silently truncated to exactly the cap.
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read vendored circuit file %s: %w", path, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("vendored circuit file %s exceeds the %d byte cap", path, maxBytes)
	}
	return data, nil
}

// filePathFromURL converts a file:// URL to a local path.
//
// Only an empty or "localhost" host is accepted: file://host/share is a
// UNC-style reference to another machine, which is a network fetch wearing
// a local scheme and not what a vendored mirror is.
func filePathFromURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse file URL %q: %w", rawURL, err)
	}
	if parsed.Scheme != "file" {
		return "", fmt.Errorf("not a file URL: %q", rawURL)
	}
	if parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost") {
		return "", fmt.Errorf("file URL %q names host %q: only a local path is supported", rawURL, parsed.Host)
	}

	path := parsed.Path
	if path == "" {
		return "", fmt.Errorf("file URL %q has no path", rawURL)
	}
	// file:///C:/x on Windows parses to "/C:/x".
	if runtime.GOOS == "windows" {
		path = strings.TrimPrefix(path, "/")
	}
	return filepath.FromSlash(path), nil
}

// ValidCircuitID reports whether id is safe to interpolate into a catalog
// path.
//
// FetchCircuit's id comes from a presented proof's zkSystemId on the
// verifier side, so it is attacker-influenced. Against the HTTP service a
// crafted id could reach a path on the source that is not a circuit
// descriptor; against a vendored mirror it is a direct filesystem read,
// where "vega/../../../etc/passwd" would otherwise escape the mirror
// entirely. Catalog ids are flat tokens - "vega-mc-p256-v1-prover-key-r12",
// "longfellow-libzk-v1_8_2_4307_2945" - so anything carrying a separator,
// a percent-escape or a dot segment is not an id and is refused rather
// than sanitised into one.
func ValidCircuitID(id string) bool {
	if id == "" || len(id) > 256 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	// Rejected after the character scan so "." and ".." - which pass it -
	// are still refused.
	return id != "." && id != ".."
}

// SafeRelativeArtifactPath returns the mirror-relative path an artifact is
// stored at, or an error if the descriptor's URL is not one.
//
// The real catalog serves artifact URLs as relative paths like
// "v1/artifacts/sha256/<hex>", resolved against each configured source.
// That path is REMOTE DATA, and it is joined onto a local directory by the
// vendoring tool and onto a file:// source by this client - so "../../x"
// in a descriptor reads or writes outside the mirror entirely, before any
// hash verification can have an opinion. Absolute URLs are not this
// function's business and are refused here; DownloadArtifact handles them
// separately.
func SafeRelativeArtifactPath(rawURL string) (string, error) {
	if rawURL == "" {
		return "", errors.New("artifact URL is empty")
	}
	if absoluteURLScheme(rawURL) != "" {
		return "", fmt.Errorf("artifact URL %q is absolute, not a mirror-relative path", rawURL)
	}
	if strings.ContainsAny(rawURL, "?#\\") {
		return "", fmt.Errorf("artifact path %q contains a query, fragment or backslash", rawURL)
	}

	trimmed := strings.TrimPrefix(rawURL, "/")
	cleaned := path.Clean(trimmed)
	// Clean collapses "a/../b" to "b" and leaves an escaping path starting
	// with "..", so comparing against it catches both the blatant
	// "../../etc" and the roundabout "v1/../../etc".
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("artifact path %q escapes the mirror root", rawURL)
	}
	return cleaned, nil
}
