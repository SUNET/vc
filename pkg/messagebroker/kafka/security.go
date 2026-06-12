package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SUNET/vc/pkg/model"

	"github.com/IBM/sarama"
)

// applySecurityConfig applies SASL and TLS settings from cfg to the Sarama configuration.
func applySecurityConfig(saramaConfig *sarama.Config, cfg *model.Cfg) error {
	if cfg == nil || cfg.Common == nil {
		return nil
	}
	kafka := &cfg.Common.Kafka

	// SASL
	if kafka.SASL != nil && kafka.SASL.Enable {
		saramaConfig.Net.SASL.Enable = true
		saramaConfig.Net.SASL.User = kafka.SASL.Username
		saramaConfig.Net.SASL.Password = kafka.SASL.Password

		switch kafka.SASL.Mechanism {
		case "SCRAM-SHA-256":
			saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: SHA256} }
			saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		case "SCRAM-SHA-512":
			saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: SHA512} }
			saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
		case "PLAIN":
			saramaConfig.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		default:
			return fmt.Errorf("unsupported SASL mechanism %q; supported values are SCRAM-SHA-256, SCRAM-SHA-512, PLAIN", kafka.SASL.Mechanism)
		}
	}

	// mTLS
	if kafka.MTLS.Enable {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// Load CA cert if provided
		if kafka.MTLS.CACertPath != "" {
			caCert, err := os.ReadFile(filepath.Clean(kafka.MTLS.CACertPath))
			if err != nil {
				return fmt.Errorf("reading CA cert %q: %w", kafka.MTLS.CACertPath, err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("parsing CA cert %q: no valid certificates found", kafka.MTLS.CACertPath)
			}
			tlsConfig.RootCAs = caCertPool
		}

		// Load client cert/key for mTLS — required when mTLS is enabled
		if kafka.MTLS.CertFilePath == "" || kafka.MTLS.KeyFilePath == "" {
			return fmt.Errorf("kafka mTLS is enabled but cert_file_path and key_file_path must both be set")
		}
		cert, err := tls.LoadX509KeyPair(
			filepath.Clean(kafka.MTLS.CertFilePath),
			filepath.Clean(kafka.MTLS.KeyFilePath),
		)
		if err != nil {
			return fmt.Errorf("loading client cert/key (%q, %q): %w", kafka.MTLS.CertFilePath, kafka.MTLS.KeyFilePath, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		tlsConfig.InsecureSkipVerify = kafka.MTLS.InsecureSkipVerify //nolint:gosec // configurable for testing only

		saramaConfig.Net.TLS.Enable = true
		saramaConfig.Net.TLS.Config = tlsConfig
	}

	return nil
}
