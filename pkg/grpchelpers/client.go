package grpchelpers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/SUNET/vc/pkg/model"
)

// NewClientConn creates a gRPC client connection with optional mTLS support.
// If TLS is disabled, returns an insecure connection.
// If TLS is enabled without client certs, uses server-only TLS.
// If TLS is enabled with client certs, uses mutual TLS (mTLS).
//
// No automatic retry policy is configured because several services exposed
// over these connections are non-idempotent (e.g. MakeSDJWT, MakeMDoc,
// TokenStatusListAddStatus). Retrying UNAVAILABLE after the server has
// already processed a request would risk duplicating credentials or status
// list entries. Callers that need retries for specific idempotent RPCs
// should implement them at the application level.
func NewClientConn(cfg model.GRPCClientTLS) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{}

	if !cfg.TLS {
		// Insecure connection
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		return grpc.NewClient(cfg.Addr, opts...)
	}

	// Build TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Prefer TLS 1.3; restrict TLS 1.2 cipher suites to secure AEAD ciphers only
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.X25519},
	}

	// Load CA certificate if specified
	if cfg.CAFilePath != "" {
		caCert, err := os.ReadFile(cfg.CAFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caPool
	}

	// Load client certificate for mTLS if specified
	if cfg.CertFilePath != "" && cfg.KeyFilePath != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.CertFilePath, cfg.KeyFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	// Set server name for TLS verification if specified
	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	}

	creds := credentials.NewTLS(tlsConfig)
	opts = append(opts, grpc.WithTransportCredentials(creds))

	conn, err := grpc.NewClient(cfg.Addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client connection: %w", err)
	}

	return conn, nil
}
