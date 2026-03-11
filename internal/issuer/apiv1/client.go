package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/internal/issuer/auditlog"
	"vc/pkg/grpchelpers"
	"vc/pkg/logger"
	"vc/pkg/mdoc"
	"vc/pkg/model"
	"vc/pkg/pki"
	"vc/pkg/trace"

	"google.golang.org/grpc"
)

//	@title		Issuer API
//	@version	0.1.0
//	@BasePath	/issuer/api/v1

// Client holds the public api object
type Client struct {
	cfg            *model.Cfg
	log            *logger.Log
	tracer         *trace.Tracer
	auditLog       *auditlog.Service
	signer         pki.Signer
	privateKey     any // Raw key (*ecdsa.PrivateKey or *rsa.PrivateKey) needed for mDL COSE signing and VC 2.0 Data Integrity proofs (ecdsa-rdfc-2019, eddsa-rdfc-2022) which require direct key access beyond the pki.Signer interface
	jwkProto       *apiv1_issuer.Jwk
	registryConn   *grpc.ClientConn
	registryClient apiv1_registry.RegistryServiceClient
	mdocIssuer     *mdoc.Issuer // mDL issuer for ISO 18013-5 credentials
}

// New creates a new instance of the public api
func New(ctx context.Context, auditLog *auditlog.Service, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:      cfg,
		log:      log.New("apiv1"),
		tracer:   tracer,
		auditLog: auditLog,
		jwkProto: &apiv1_issuer.Jwk{},
	}

	if err := c.initSigner(ctx); err != nil {
		return nil, err
	}

	if err := c.initRegistryClient(ctx); err != nil {
		return nil, err
	}

	// Initialize mDL issuer if certificate chain is configured
	if err := c.initMDocIssuer(ctx); err != nil {
		c.log.Info("mDL issuer not initialized", "error", err)
		// Non-fatal: mDL issuance will be unavailable but SD-JWT will work
	}

	c.log.Info("Started")

	return c, nil
}

// initSigner initializes the signing service (software or PKCS#11)
func (c *Client) initSigner(ctx context.Context) error {
	// Load key material using KeyConfig (supports both file and HSM)
	keyLoader := pki.NewKeyLoader()
	km, err := keyLoader.LoadKeyMaterial(c.cfg.Issuer.KeyConfig)
	if err != nil {
		c.log.Error(err, "Failed to load signing key")
		return fmt.Errorf("failed to load signing key: %w", err)
	}

	// Create signer from key material
	c.signer = pki.NewKeyMaterialSigner(km)

	// Store private key for mDL issuer and VC 2.0 Data Integrity signing
	c.privateKey = km.PrivateKey

	c.log.Info("Initialized signing key", "algorithm", c.signer.Algorithm(), "keyID", c.signer.KeyID())

	if err := c.createJWK(ctx); err != nil {
		return err
	}

	return nil
}

// initRegistryClient initializes the gRPC client connection to the registry service
func (c *Client) initRegistryClient(ctx context.Context) error {
	cfg := c.cfg.Issuer.RegistryClient
	if cfg.Addr == "" {
		c.log.Info("Registry client not configured, skipping initialization")
		return nil
	}

	conn, err := grpchelpers.NewClientConn(cfg)
	if err != nil {
		return fmt.Errorf("failed to create registry client connection: %w", err)
	}

	c.registryConn = conn
	c.registryClient = apiv1_registry.NewRegistryServiceClient(conn)

	c.log.Info("Registry client initialized", "addr", cfg.Addr, "tls_enabled", cfg.TLS)
	return nil
}

// initMDocIssuer initializes the mDL issuer for ISO 18013-5 credentials
func (c *Client) initMDocIssuer(ctx context.Context) error {
	// Check if mDL configuration is available
	if c.cfg.Issuer.MDoc == nil {
		return fmt.Errorf("mDL configuration not found")
	}

	mdocCfg := c.cfg.Issuer.MDoc

	// Read and parse the certificate chain
	if mdocCfg.CertificateChainPath == "" {
		return fmt.Errorf("certificate chain path not configured for mDL")
	}

	certChain, err := c.loadCertificateChain(mdocCfg.CertificateChainPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate chain: %w", err)
	}

	// Get the signing key - reuse the existing private key if it's ECDSA
	var signerKey *ecdsa.PrivateKey
	switch key := c.privateKey.(type) {
	case *ecdsa.PrivateKey:
		signerKey = key
	default:
		return fmt.Errorf("mDL requires ECDSA signing key, got %T", c.privateKey)
	}

	// Create the mDL issuer
	issuer, err := mdoc.NewIssuer(mdoc.IssuerConfig{
		SignerKey:        signerKey,
		CertificateChain: certChain,
		DefaultValidity:  mdocCfg.DefaultValidity,
		DigestAlgorithm:  mdoc.DigestAlgorithm(mdocCfg.DigestAlgorithm),
	})
	if err != nil {
		return fmt.Errorf("failed to create mDL issuer: %w", err)
	}

	c.mdocIssuer = issuer
	c.log.Info("mDL issuer initialized", "cert_chain_length", len(certChain))
	return nil
}

// loadCertificateChain loads X.509 certificates from a PEM file
func (c *Client) loadCertificateChain(path string) ([]*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		certPEM = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in file")
	}

	return certs, nil
}

// Close closes all client connections
func (c *Client) Close() error {
	if c.registryConn != nil {
		return c.registryConn.Close()
	}
	return nil
}

// RegistryClient returns the registry gRPC client, may be nil if not configured
func (c *Client) RegistryClient() apiv1_registry.RegistryServiceClient {
	return c.registryClient
}
