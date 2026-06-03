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

// defaultServiceConfig is a gRPC service config that enables transparent
// retries for transient failures (UNAVAILABLE — e.g. connection refused,
// DNS resolution failures, brief network blips).  The policy applies to
// every unary RPC on every service.
//
// maxAttempts=5 with very short backoff (20 ms → 40 ms → 80 ms → 100 ms)
// keeps total added latency under ~250 ms so synchronous flows like
// credential issuance stay responsive for the waiting user.
const defaultServiceConfig = `{
	"methodConfig": [{
		"name": [{"service": ""}],
		"retryPolicy": {
			"maxAttempts": 5,
			"initialBackoff": "0.02s",
			"maxBackoff": "0.1s",
			"backoffMultiplier": 2.0,
			"retryableStatusCodes": ["UNAVAILABLE"]
		}
	}]
}`

// NewClientConn creates a gRPC client connection with optional mTLS support.
// If TLS is disabled, returns an insecure connection.
// If TLS is enabled without client certs, uses server-only TLS.
// If TLS is enabled with client certs, uses mutual TLS (mTLS).
//
// All connections are configured with a default retry policy that
// transparently retries UNAVAILABLE errors with exponential backoff.
func NewClientConn(cfg model.GRPCClientTLS) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithDefaultServiceConfig(defaultServiceConfig),
	}

	if !cfg.TLS {
		// Insecure connection
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		return grpc.NewClient(cfg.Addr, opts...)
	}

	// Build TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
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
