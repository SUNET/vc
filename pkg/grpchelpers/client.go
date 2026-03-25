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
func NewClientConn(cfg model.GRPCClientTLS) (*grpc.ClientConn, error) {
	if !cfg.TLS {
		// Insecure connection
		return grpc.NewClient(cfg.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	conn, err := grpc.NewClient(cfg.Addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client connection: %w", err)
	}

	return conn, nil
}
