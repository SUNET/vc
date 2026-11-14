// Package lote — LoTE signer trust anchor interface.
//
// LoTETrustAnchorProvider is the extension point for LoTE JWS signature
// verification per ETSI TS 119 615. Callers inject their own implementation;
// the core library ships a no-op that skips verification for environments
// where the LoTE source is already considered trustworthy (e.g. in tests or
// deployments that verify authenticity through other means such as HTTPS
// pinning or a controlled internal distribution).
//
// An OJEU-anchored implementation (for APTITUDE/EUDI production use) belongs
// outside this package because the OJEU endpoint address is
// deployment-specific.
package lote

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoTETrustAnchorProvider supplies the root certificates used to anchor the
// LoTE signer certificate chain during JWS signature verification. Implementations
// decide how and where to obtain the roots (e.g. from OJEU, from a local file,
// or from a pinned certificate bundle).
//
// TrustAnchors is called once per LoTE load. It may return a cached set.
// Returning a nil pool with a nil error disables signature verification for
// that call (equivalent to NilTrustAnchorProvider).
type LoTETrustAnchorProvider interface {
	TrustAnchors(ctx context.Context) (*x509.CertPool, error)
}

// NilTrustAnchorProvider is the no-op implementation of LoTETrustAnchorProvider.
// It returns a nil pool, causing JWS signature verification to be skipped.
// Use this when the LoTE source is trusted through other means (HTTPS,
// controlled distribution) or in test environments.
type NilTrustAnchorProvider struct{}

// TrustAnchors returns nil, nil — signature verification is skipped.
func (NilTrustAnchorProvider) TrustAnchors(_ context.Context) (*x509.CertPool, error) {
	return nil, nil
}

// StaticTrustAnchorProvider holds a fixed CertPool. Useful for testing and
// for deployments where the root certificates are managed out-of-band.
type StaticTrustAnchorProvider struct {
	pool *x509.CertPool
}

// NewStaticTrustAnchorProvider creates a provider with the given root certificates.
// If pool is nil the behaviour is the same as NilTrustAnchorProvider.
func NewStaticTrustAnchorProvider(pool *x509.CertPool) *StaticTrustAnchorProvider {
	return &StaticTrustAnchorProvider{pool: pool}
}

// TrustAnchors returns the configured pool.
func (p *StaticTrustAnchorProvider) TrustAnchors(_ context.Context) (*x509.CertPool, error) {
	return p.pool, nil
}

// LoadTrustAnchorBundle reads a PEM file of CA certificates and returns a
// StaticTrustAnchorProvider over them. It is strict, because this is the
// pinned root of trust for LoTE signatures: an unreadable file, a CERTIFICATE
// block that does not parse, or a file with no certificate at all is an error
// (a silently shrunken anchor set would make verification fail confusingly or,
// worse, mask a pinning mistake). Non-CERTIFICATE PEM blocks are ignored.
func LoadTrustAnchorBundle(path string) (*StaticTrustAnchorProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lote: reading trust anchor bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	n := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("lote: trust anchor bundle %s: invalid certificate #%d: %w", path, n+1, err)
		}
		pool.AddCert(cert)
		n++
	}
	// pem.Decode stops (returns nil) at the first malformed block and leaves it
	// in rest; do not let a valid anchor mask a corrupt one after it.
	if bytes.Contains(rest, []byte("-----BEGIN ")) {
		return nil, fmt.Errorf("lote: trust anchor bundle %s: malformed PEM block after certificate #%d", path, n)
	}
	if n == 0 {
		return nil, fmt.Errorf("lote: trust anchor bundle %s contains no certificates", path)
	}
	return NewStaticTrustAnchorProvider(pool), nil
}
