package grpchelpers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"vc/pkg/model"
)

// NewServerOptions returns gRPC server options with optional TLS/mTLS support.
// If TLS is disabled, returns nil (for insecure server).
// If TLS is enabled without client CA, uses server-only TLS.
// If TLS is enabled with client CA, uses mutual TLS (mTLS) requiring client certificates.
// If AllowedClientFingerprints or AllowedClientDNs is set, adds an interceptor to verify client certs.
func NewServerOptions(cfg model.GRPCServer) ([]grpc.ServerOption, error) {
	if !cfg.TLS.Enabled {
		return nil, nil
	}

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(cfg.TLS.CertFilePath, cfg.TLS.KeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	// If client CA is specified, enable mTLS (mutual TLS)
	if cfg.TLS.ClientCAPath != "" {
		clientCA, err := os.ReadFile(cfg.TLS.ClientCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA certificate: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(clientCA) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caPool
	}

	creds := credentials.NewTLS(tlsConfig)
	opts := []grpc.ServerOption{grpc.Creds(creds)}

	// Add client identity verification interceptor if any allowlist is configured
	allowedFingerprints, allowedDNs := buildClientAllowlists(cfg.TLS)
	if allowedFingerprints != nil || allowedDNs != nil {
		interceptor := clientAuthUnaryInterceptor(allowedFingerprints, allowedDNs)
		streamInterceptor := clientAuthStreamInterceptor(allowedFingerprints, allowedDNs)
		opts = append(opts,
			grpc.UnaryInterceptor(interceptor),
			grpc.StreamInterceptor(streamInterceptor),
		)
	}

	return opts, nil
}

// buildClientAllowlists normalizes the fingerprint and DN allowlists from the TLS config.
// Returns nil maps when the respective allowlist is not configured.
func buildClientAllowlists(tlsCfg model.GRPCTLS) (allowedFingerprints, allowedDNs map[string]string) {
	if len(tlsCfg.AllowedClientFingerprints) > 0 {
		allowedFingerprints = make(map[string]string, len(tlsCfg.AllowedClientFingerprints))
		for fp, name := range tlsCfg.AllowedClientFingerprints {
			allowedFingerprints[normalizeFingerprint(fp)] = name
		}
	}

	if len(tlsCfg.AllowedClientDNs) > 0 {
		allowedDNs = make(map[string]string, len(tlsCfg.AllowedClientDNs))
		for dn, name := range tlsCfg.AllowedClientDNs {
			allowedDNs[normalizeDN(dn)] = name
		}
	}

	return allowedFingerprints, allowedDNs
}

// normalizeFingerprint normalizes a fingerprint string for comparison.
// Removes "SHA256:" prefix, colons, spaces, and converts to lowercase.
func normalizeFingerprint(fp string) string {
	fp = strings.ToLower(fp)
	fp = strings.TrimPrefix(fp, "sha256:")
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, " ", "")
	return fp
}

// CertFingerprint calculates the SHA256 fingerprint of a certificate.
// Returns the fingerprint as a lowercase hex string.
func CertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// FormatFingerprint formats a fingerprint with colons for display (e.g., "aa:bb:cc:dd...")
func FormatFingerprint(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 2 {
		end := i + 2
		if end > len(fp) {
			end = len(fp)
		}
		parts = append(parts, fp[i:end])
	}
	return "SHA256:" + strings.Join(parts, ":")
}

// normalizeDN normalizes a Distinguished Name string for comparison.
// Trims whitespace and converts to lowercase for case-insensitive matching.
func normalizeDN(dn string) string {
	return strings.ToLower(strings.TrimSpace(dn))
}

// CertDN returns the Subject Distinguished Name of a certificate as a string.
// Uses the standard RFC 2253 / Go x509 String() format.
func CertDN(cert *x509.Certificate) string {
	return cert.Subject.String()
}

// clientAuthUnaryInterceptor returns a unary interceptor that verifies client certs
// against both fingerprint and DN allowlists. A client is allowed if it matches EITHER list.
func clientAuthUnaryInterceptor(allowedFingerprints, allowedDNs map[string]string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := verifyClientIdentity(ctx, allowedFingerprints, allowedDNs); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// clientAuthStreamInterceptor returns a stream interceptor that verifies client certs
// against both fingerprint and DN allowlists. A client is allowed if it matches EITHER list.
func clientAuthStreamInterceptor(allowedFingerprints, allowedDNs map[string]string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := verifyClientIdentity(ss.Context(), allowedFingerprints, allowedDNs); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// verifyClientIdentity extracts the client certificate from the context and verifies it
// against fingerprint and/or DN allowlists. The client is allowed if it matches EITHER list.
// This supports both pinned certificates (via fingerprints) and dynamic certificates like
// ACME/Let's Encrypt (via DN matching).
func verifyClientIdentity(ctx context.Context, allowedFingerprints, allowedDNs map[string]string) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer info")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "no TLS info")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "no client certificate")
	}

	clientCert := tlsInfo.State.PeerCertificates[0]

	// Check fingerprint allowlist
	if len(allowedFingerprints) > 0 {
		fingerprint := CertFingerprint(clientCert)
		if _, allowed := allowedFingerprints[fingerprint]; allowed {
			return nil
		}
	}

	// Check DN allowlist
	if len(allowedDNs) > 0 {
		dn := normalizeDN(CertDN(clientCert))
		if _, allowed := allowedDNs[dn]; allowed {
			return nil
		}
	}

	// Build informative error message
	fingerprint := CertFingerprint(clientCert)
	dn := CertDN(clientCert)
	return status.Errorf(codes.PermissionDenied,
		"client certificate not in allowlist: fingerprint=%s, dn=%q", FormatFingerprint(fingerprint), dn)
}

// fingerprintUnaryInterceptor returns a unary interceptor that verifies client cert fingerprints.
// allowedFingerprints maps normalized fingerprint -> friendly name.
// Deprecated: Use clientAuthUnaryInterceptor instead which supports both fingerprints and DNs.
func fingerprintUnaryInterceptor(allowedFingerprints map[string]string) grpc.UnaryServerInterceptor {
	return clientAuthUnaryInterceptor(allowedFingerprints, nil)
}

// fingerprintStreamInterceptor returns a stream interceptor that verifies client cert fingerprints.
// allowedFingerprints maps normalized fingerprint -> friendly name.
// Deprecated: Use clientAuthStreamInterceptor instead which supports both fingerprints and DNs.
func fingerprintStreamInterceptor(allowedFingerprints map[string]string) grpc.StreamServerInterceptor {
	return clientAuthStreamInterceptor(allowedFingerprints, nil)
}

// verifyClientFingerprint extracts the client certificate from the context and verifies its fingerprint.
// allowedFingerprints maps normalized fingerprint -> friendly name.
// Deprecated: Use verifyClientIdentity instead which supports both fingerprints and DNs.
func verifyClientFingerprint(ctx context.Context, allowedFingerprints map[string]string) error {
	return verifyClientIdentity(ctx, allowedFingerprints, nil)
}
