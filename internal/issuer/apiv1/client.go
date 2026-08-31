package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/internal/issuer/auditlog"
	"github.com/SUNET/vc/pkg/bbs"
	"github.com/SUNET/vc/pkg/grpchelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/trace"

	"google.golang.org/grpc"
)

//	@title		Issuer API
//	@version	0.1.0
//	@BasePath	/issuer/api/v1

// Client holds the public api object
type Client struct {
	cfg         *model.Cfg
	log         *logger.Log
	tracer      *trace.Tracer
	auditLog    *auditlog.Service
	signer      pki.Signer
	signerChain []string // Base64-encoded DER x5c certificate chain (optional)
	// metadataSigner and metadataChain sign Credential Issuer Metadata. They
	// are the access certificate (WRPAC) when one is configured, and fall
	// back to the credential signer above when it is not.
	metadataSigner pki.Signer
	metadataChain  []string
	signingCert    *x509.Certificate // Leaf of signerChain, kept for profile validation
	privateKey     any               // Raw key (*ecdsa.PrivateKey or *rsa.PrivateKey) needed for mDL COSE signing and VC 2.0 Data Integrity proofs (ecdsa-rdfc-2019, eddsa-rdfc-2022) which require direct key access beyond the pki.Signer interface
	jwkProto       *apiv1_issuer.Jwk
	registryConn   *grpc.ClientConn
	registryClient apiv1_registry.RegistryServiceClient
	mdocIssuer     *mdoc.Issuer // mDL issuer for ISO 18013-5 credentials
	signMetadataRL *rate.Limiter
	bbsKeys        *bbsKeyPair // nil unless Issuer.BBS is configured; gates the "jwp" format
	// bbsIssuerOverride replaces the native signer in tests.
	//
	// A seam rather than a design choice: without it nothing could show
	// that MakeJWP passes the caller's suite *through* to the signer, only
	// that it rejects the ones it should. Those are different properties,
	// and hardcoding the suite again passed every test until this existed.
	bbsIssuerOverride bbs.Issuer
}

// bbsKeyPair is the issuer's BLS12-381 key pair, held as raw bytes.
//
// Raw bytes rather than a pki.Signer because it cannot be one: the secret is
// a scalar consumed inside the BBS signing algebra, not a key that signs a
// digest. See model.BBSConfig for why that rules out an HSM.
type bbsKeyPair struct {
	secret []byte
	public []byte
}

// New creates a new instance of the public api
func New(ctx context.Context, auditLog *auditlog.Service, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:            cfg,
		log:            log.New("apiv1"),
		tracer:         tracer,
		auditLog:       auditLog,
		jwkProto:       &apiv1_issuer.Jwk{},
		signMetadataRL: rate.NewLimiter(rate.Limit(cfg.Issuer.SignMetadataRateLimit.RequestsPerSecond), cfg.Issuer.SignMetadataRateLimit.Burst),
	}

	if err := c.initSigner(ctx); err != nil {
		return nil, err
	}

	if err := c.initAccessCertificate(ctx); err != nil {
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

	// Fatal, unlike the mDL case above: mDL is unconfigured by default and
	// an absent certificate chain means "not offering that format". A
	// present but unloadable BBS config means the operator asked for the
	// format and it is broken, which should not start quietly and fail one
	// request at a time.
	if err := c.initBBSKeys(); err != nil {
		return nil, err
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
	c.signerChain = km.Chain
	c.signingCert = km.Cert

	// Store private key for mDL issuer and VC 2.0 Data Integrity signing
	c.privateKey = km.PrivateKey

	c.log.Info("Initialized signing key", "algorithm", c.signer.Algorithm(), "keyID", c.signer.KeyID(), "x5c_certs", len(km.Chain))

	if err := c.createJWK(ctx); err != nil {
		return err
	}

	return nil
}

// initAccessCertificate loads the access certificate (WRPAC) that issuer
// metadata is signed with, and validates it against the WRPAC profile.
//
// The access certificate is what authenticates the issuer to a wallet, so it
// is deliberately separate from the credential key: that key is published in
// /jwks and signs credentials, and the two rotate independently.
//
// When no access certificate is configured the credential key is used
// instead and a warning is logged. That is a degraded configuration rather
// than an error, so an existing deployment keeps booting across an upgrade -
// but it means wallets see metadata signed by a certificate that was never
// meant to identify the issuer to them.
func (c *Client) initAccessCertificate(_ context.Context) error {
	keyConfig := c.cfg.Issuer.AccessCertificateKeyConfig()
	if keyConfig == nil {
		c.metadataSigner = c.signer
		c.metadataChain = c.signerChain

		// Still validate whatever we will actually present, so opting into
		// validation without a separate key is honest rather than vacuous.
		if err := c.cfg.Issuer.ValidateAccessCertificate(c.signingCert, time.Now()); err != nil {
			return fmt.Errorf("access certificate validation failed: %w", err)
		}
		if c.cfg.Issuer.AccessCertificate != nil {
			c.log.Warn("no access certificate key configured; signing issuer metadata with the credential key",
				"remedy", "set issuer.access_certificate.key_config")
		}
		return nil
	}

	signer, leaf, chain, err := pki.LoadSigner(keyConfig)
	if err != nil {
		return fmt.Errorf("failed to load access certificate key: %w", err)
	}

	// A key without its certificate is not an access certificate. It would
	// load, sign metadata, and emit no x5c - leaving a wallet with no way to
	// verify or chain the signature, which is the entire purpose of
	// configuring one. Refuse it rather than start in a configuration that
	// looks enabled and achieves nothing.
	if leaf == nil || len(chain) == 0 {
		return fmt.Errorf("issuer.access_certificate.key_config loads a key but no certificate: set chain_path, otherwise issuer metadata is signed without an x5c header and wallets cannot verify it")
	}

	if err := c.cfg.Issuer.ValidateAccessCertificate(leaf, time.Now()); err != nil {
		return fmt.Errorf("access certificate validation failed: %w", err)
	}

	c.metadataSigner = signer
	c.metadataChain = chain
	c.log.Info("Initialized access certificate for issuer metadata",
		"algorithm", signer.Algorithm(), "keyID", signer.KeyID(), "x5c_certs", len(chain))
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

	pseudonymSeed := false
	if c.cfg.Issuer.PseudonymSeed != nil {
		pseudonymSeed = *c.cfg.Issuer.PseudonymSeed
	}

	// Create the mDL issuer
	issuer, err := mdoc.NewIssuer(mdoc.IssuerConfig{
		SignerKey:        signerKey,
		CertificateChain: certChain,
		DefaultValidity:  mdocCfg.DefaultValidity,
		DigestAlgorithm:  mdoc.DigestAlgorithm(mdocCfg.DigestAlgorithm),
		PseudonymSeed:    pseudonymSeed,
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
	certPEM, err := os.ReadFile(filepath.Clean(path))
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
			cert, err := pki.ParseCertificate(block.Bytes, nil)
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

// GetIACAs returns the IACA certificates from the mDOC certificate chain.
// IACA certificates are the non-leaf certificates (index 1+) in the chain.
func (c *Client) GetIACAs(_ context.Context) (*apiv1_issuer.GetIACAsReply, error) {
	if c.mdocIssuer == nil {
		return nil, fmt.Errorf("mDOC issuer not configured")
	}

	chain := c.mdocIssuer.CertificateChain()
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	// IACA certs are everything after the DS (leaf) cert.
	// If only one cert (self-signed), return it as the IACA.
	startIdx := 1
	if len(chain) == 1 {
		startIdx = 0
	}

	reply := &apiv1_issuer.GetIACAsReply{
		Certificates: make([][]byte, 0, len(chain)-startIdx),
	}
	for i := startIdx; i < len(chain); i++ {
		reply.Certificates = append(reply.Certificates, chain[i].Raw)
	}

	return reply, nil
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

// initBBSKeys loads the issuer's BBS key pair, if this issuer offers the
// format at all.
//
// An absent Issuer.BBS section is not an error: it means this deployment
// does not issue blind BBS credentials, and MakeJWP will say so rather than
// signing with a zero key.
func (c *Client) initBBSKeys() error {
	if c.cfg.Issuer == nil || c.cfg.Issuer.BBS == nil {
		c.log.Info("BBS issuance not configured")
		return nil
	}
	cfg := c.cfg.Issuer.BBS

	secret, err := bbsKeyMaterial("secret", cfg.SecretKeyPath, cfg.SecretKey)
	if err != nil {
		return err
	}
	public, err := bbsKeyMaterial("public", cfg.PublicKeyPath, cfg.PublicKey)
	if err != nil {
		return err
	}

	// Check the two halves actually form a pair. This was previously left
	// undone because the crate exposed no way to derive a public key from a
	// secret one, and a length check would have confirmed the widths and
	// nothing about whether the pair is a pair; zk-cred-bbs v0.0.7 added
	// SkToPk, so it can be checked properly.
	//
	// Worth the one derivation at startup: a mismatched pair signs
	// perfectly well, and what fails is every verification afterwards,
	// reporting only "does not verify" - a failure with nothing in it
	// pointing at the configuration that caused it.
	//
	// Skipped when the native library is absent, because then there is no
	// deriver and no issuance either: MakeJWP fails on its own with a
	// clearer message than a startup error about an unavailable backend
	// would give.
	if bbs.Available() {
		if err := bbs.KeyPairMatches(bbs.Native(), secret, public); err != nil {
			return err
		}
	} else {
		c.log.Info("BBS keys loaded but not verified: this build has no native BBS support")
	}

	c.bbsKeys = &bbsKeyPair{secret: secret, public: public}
	c.log.Info("Initialized BBS issuance key")
	return nil
}

// bbsKeyMaterial resolves one half of the key pair from whichever of the
// two ways it was configured.
//
// Both set, or neither, is refused rather than resolved by precedence. A
// deployment that sets both has two sources of truth for a signing key and
// no way to tell which one is live; silently preferring one would mean an
// operator can edit the wrong half and see no effect at all.
func bbsKeyMaterial(which, path, inline string) ([]byte, error) {
	switch {
	case path != "" && inline != "":
		return nil, fmt.Errorf("BBS %s key: set %s_key_path or %s_key, not both", which, which, which)
	case path != "":
		decoded, err := readBase64URLFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load BBS %s key: %w", which, err)
		}
		return decoded, nil
	case inline != "":
		decoded, err := decodeBase64URL(inline)
		if err != nil {
			return nil, fmt.Errorf("failed to load BBS %s key: %w", which, err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("BBS %s key: set either %s_key_path or %s_key", which, which, which)
	}
}

// decodeBase64URL decodes a single unpadded base64url value.
func decodeBase64URL(value string) ([]byte, error) {
	// Trailing whitespace is what every editor and heredoc leaves behind;
	// padding is what a standard-base64 tool leaves behind. Neither is a
	// broken key.
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(value), "="))
	if err != nil {
		return nil, fmt.Errorf("not valid base64url: %w", err)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("is empty")
	}
	return decoded, nil
}

// readBase64URLFile reads a file holding a single base64url-encoded value.
func readBase64URLFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Trailing newlines are what every editor and every `echo -n`-less
	// pipeline leaves behind; rejecting them would be a needless trap.
	decoded, err := decodeBase64URL(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s %w", path, err)
	}
	return decoded, nil
}

// bbsIssuer is the signer MakeJWP blind-signs with — the native one unless
// a test has replaced it.
func (c *Client) bbsIssuer() bbs.Issuer {
	if c.bbsIssuerOverride != nil {
		return c.bbsIssuerOverride
	}
	return bbs.Native()
}
