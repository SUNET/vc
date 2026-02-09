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
// If AllowedClientFingerprints is set, adds an interceptor to verify client cert fingerprints.
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

	// Add fingerprint verification interceptor if allowlist is configured
	if len(cfg.TLS.AllowedClientFingerprints) > 0 {
		// Build normalized allowlist: normalized fingerprint -> friendly name
		allowedSet := make(map[string]string, len(cfg.TLS.AllowedClientFingerprints))
		for fp, name := range cfg.TLS.AllowedClientFingerprints {
			// Normalize: remove "SHA256:" prefix if present, lowercase, remove colons
			normalized := normalizeFingerprint(fp)
			allowedSet[normalized] = name
		}

		interceptor := fingerprintUnaryInterceptor(allowedSet)
		streamInterceptor := fingerprintStreamInterceptor(allowedSet)
		opts = append(opts,
			grpc.UnaryInterceptor(interceptor),
			grpc.StreamInterceptor(streamInterceptor),
		)
	}

	return opts, nil
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

// fingerprintUnaryInterceptor returns a unary interceptor that verifies client cert fingerprints.
// allowedFingerprints maps normalized fingerprint -> friendly name.
func fingerprintUnaryInterceptor(allowedFingerprints map[string]string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := verifyClientFingerprint(ctx, allowedFingerprints); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// fingerprintStreamInterceptor returns a stream interceptor that verifies client cert fingerprints.
// allowedFingerprints maps normalized fingerprint -> friendly name.
func fingerprintStreamInterceptor(allowedFingerprints map[string]string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := verifyClientFingerprint(ss.Context(), allowedFingerprints); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// verifyClientFingerprint extracts the client certificate from the context and verifies its fingerprint.
// allowedFingerprints maps normalized fingerprint -> friendly name.
func verifyClientFingerprint(ctx context.Context, allowedFingerprints map[string]string) error {
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
	fingerprint := CertFingerprint(clientCert)

	if _, allowed := allowedFingerprints[fingerprint]; !allowed {
		return status.Errorf(codes.PermissionDenied, "client certificate fingerprint not in allowlist: %s", FormatFingerprint(fingerprint))
	}

	return nil
}
