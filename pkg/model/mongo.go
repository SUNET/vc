package model

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoClientOptions returns a *options.ClientOptions configured from the
// Mongo settings. It applies the connection URI and, when TLS is enabled,
// builds the appropriate *tls.Config (CA verification and/or mTLS client
// certificate).
func (m *Mongo) MongoClientOptions() (*options.ClientOptions, error) {
	opts := options.Client().ApplyURI(m.URI)

	if !m.tlsRequired() {
		return opts, nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if m.CAFilePath != "" {
		caCert, err := os.ReadFile(m.CAFilePath)
		if err != nil {
			return nil, fmt.Errorf("mongo: failed to read CA file %q: %w", m.CAFilePath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("mongo: CA file %q contains no valid PEM certificates", m.CAFilePath)
		}
		tlsCfg.RootCAs = pool
	}

	if m.CertFilePath != "" && m.KeyFilePath != "" {
		cert, err := tls.LoadX509KeyPair(m.CertFilePath, m.KeyFilePath)
		if err != nil {
			return nil, fmt.Errorf("mongo: failed to load client certificate/key (%q, %q): %w", m.CertFilePath, m.KeyFilePath, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	opts.SetTLSConfig(tlsCfg)
	return opts, nil
}

// tlsRequired returns true when TLS should be configured on the MongoDB client.
// TLS is required when explicitly enabled or when any TLS-related file path is set.
func (m *Mongo) tlsRequired() bool {
	return m.TLS || m.CAFilePath != "" || m.CertFilePath != "" || m.KeyFilePath != ""
}
