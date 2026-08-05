package apiv1

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/grpchelpers"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/metric"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openidfederation"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

//	@title		Datastore API
//	@version	2.8
//	@BasePath	/api/v1

// Client holds the public api object
type Client struct {
	cfg        *model.Cfg
	db         *db.Service
	log        *logger.Log
	tracer     *trace.Tracer
	vciMetrics *metric.VCI

	// database collections
	credentialOfferStore db.CredentialOfferStore
	datastoreStore       db.DatastoreStore
	identityMappingStore db.IdentityMappingStore

	// gRPC clients
	issuerClient   apiv1_issuer.IssuerServiceClient
	registryClient apiv1_registry.RegistryServiceClient

	// Signing key and chain for signing metadata
	pkiSigner      pki.Signer
	pkiSigningCert *x509.Certificate
	pkiSignerChain []string

	// Metadata
	oauth2Metadata                *oauth2.AuthorizationServerMetadata
	issuerMetadata                *openid4vci.CredentialIssuerMetadataParameters
	CredentialOfferLookupMetadata *CredentialOfferLookupMetadata

	// Caches
	cacheService *cache.Service

	// Admin OIDC (when api_auth.oidc is enabled)
	adminOIDC *lazyOIDCProvider

	// Trust evaluation
	jwtTrustVerifier           *trust.JWTTrustVerifier
	walletAttestationEvaluator *trust.WalletAttestationEvaluator
	walletAttestationPolicy    *trust.WalletAttestationPolicyEngine

	// openidFederationService is nil when OpenID Federation is not enabled.
	// Built once here rather than per-request, since constructing a signer
	// forces key material to be (re)loaded every time (expensive, especially
	// with PKCS#11/HSM).
	openidFederationService *openidfederation.Service

	// issuerReachable tracks whether the issuer gRPC was reachable on the last refresh.
	// Used to log state transitions (down→up, up→down) at Info level.
	issuerReachable atomic.Bool
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, cacheService *cache.Service, tracer *trace.Tracer, meter *metric.Meter, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	vciMetrics, err := metric.NewVCI(meter.Meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create VCI metrics: %w", err)
	}

	c := &Client{
		cfg:                           cfg,
		db:                            db,
		credentialOfferStore:          db.CredentialOfferColl,
		datastoreStore:                db.DatastoreColl,
		identityMappingStore:          db.IdentityMappingsColl,
		log:                           log.New("apiv1"),
		tracer:                        tracer,
		vciMetrics:                    vciMetrics,
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
		cacheService:                  cacheService,
	}

	// Generate issuer metadata at runtime (depends on credential constructors being loaded)
	// Unsigned metadata will be signed on-demand in the handler for freshness
	c.issuerMetadata, err = c.cfg.APIGW.IssuerMetadata.Generate(ctx, c.cfg.APIGW.PublicURL, cfg.Common.CredentialMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to generate issuer metadata: %w", err)
	}

	// Load OAuth2 metadata from configuration (unsigned, will be signed on-demand if needed)
	c.oauth2Metadata = c.cfg.APIGW.Delivery.OpenID4VCI.GenerateMetadata(ctx, c.cfg.APIGW.PublicURL)

	// Load PKI signing key and chain for metadata signing
	c.pkiSigner, c.pkiSigningCert, c.pkiSignerChain, err = pki.LoadSigner(c.cfg.APIGW.KeyConfig)
	if err != nil {
		c.log.Info("PKI signing key not loaded", "error", err)
	}

	if fedCfg := cfg.APIGW.OpenIDFederation; fedCfg != nil && fedCfg.Enabled {
		fedSigner := pki.NewSignerConfig(cfg.APIGW.KeyConfig)
		c.openidFederationService = openidfederation.New(fedCfg, fedSigner, cfg.APIGW.PublicURL)
	}

	// Initialize gRPC client for issuer service
	issuerConn, err := grpchelpers.NewClientConn(cfg.APIGW.IssuerClient)
	if err != nil {
		c.log.Error(err, "Failed to create gRPC connection to issuer")
		return nil, err
	}
	c.issuerClient = apiv1_issuer.NewIssuerServiceClient(issuerConn)

	// Initialize gRPC client for registry service
	registryConn, err := grpchelpers.NewClientConn(cfg.APIGW.RegistryClient)
	if err != nil {
		c.log.Error(err, "Failed to create gRPC connection to registry")
		return nil, err
	}
	c.registryClient = apiv1_registry.NewRegistryServiceClient(registryConn)

	if err := c.CreateCredentialOfferLookupMetadata(ctx); err != nil {
		return nil, err
	}

	// Initialize OIDC provider for admin UI login (if configured).
	if cfg.APIGW.APIServer.APIAuth.OIDC.Enable {
		oidcCfg := cfg.APIGW.APIServer.APIAuth.OIDC
		c.adminOIDC = newLazyOIDCProvider(ctx, oidcCfg, c.log)
	}

	// Initialize trust evaluator for VP credential validation
	pdpURL := cfg.APIGW.Trust.PDPURL
	trustEvaluator := trust.NewTrustEvaluatorFromConfig(pdpURL)
	if pdpURL == "" {
		c.log.Warn("Trust evaluation is DISABLED - no pdp_url configured. All credential issuers will be trusted.")
	} else {
		c.log.Info("Trust evaluator initialized", "mode", "authzen", "pdp_url", pdpURL)
	}

	c.jwtTrustVerifier = trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
		TrustEvaluator: trustEvaluator,
		JWKSResolver: trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{
			HTTPClient:          &http.Client{Timeout: 30 * time.Second},
			ParseJWKToPublicKey: jose.ParseJWKToPublicKey,
		}),
		AllowedSignatureAlgorithms: cfg.APIGW.Trust.AllowedSignatureAlgorithms,
		ParseX5C:                   func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
		ParseJWK:                   jose.ParseJWKToPublicKey,
		Log:                        c.log,
	})

	// Wallet attestation: enabled when apigw.trust.wallet_attestation.enabled + pdp_url are set
	if cfg.APIGW.Trust.WalletAttestation.Enabled && pdpURL != "" {
		waMode := cfg.APIGW.Trust.WalletAttestation.Mode
		switch waMode {
		case "", trust.WIAModeETSI, trust.WIAModeIETF:
			// valid (empty = accept either format)
		default:
			c.log.Warn("apigw.trust.wallet_attestation.mode is not \"etsi\" or \"ietf\" - ignoring, accepting either WIA format",
				"configured_mode", waMode)
			waMode = ""
		}
		c.walletAttestationEvaluator = trust.NewWalletAttestationEvaluator(trustEvaluator, c.jwtTrustVerifier, waMode)

		// Build SPOCP policy engine for tier-based scope authorization (nil = default open)
		policy := cfg.APIGW.Trust.WalletAttestation.Policy
		policyEngine, err := trust.BuildWalletAttestationPolicyEngine(policy.Rules, policy.RulesFile)
		if err != nil {
			return nil, fmt.Errorf("wallet attestation policy: %w", err)
		}
		c.walletAttestationPolicy = policyEngine

		modeLabel := waMode
		if modeLabel == "" {
			modeLabel = "auto (either)"
		}
		if policyEngine != nil {
			c.log.Info("Wallet attestation enabled (PDP + SPOCP policy)",
				"rules", policyEngine.RuleCount(), "mode", modeLabel)
		} else {
			c.log.Info("Wallet attestation enabled (PDP trust, no scope restrictions)", "mode", modeLabel)
		}
	}

	c.log.Info("Started")

	return c, nil
}

// EphemeralEncryptionKey returns the ephemeral encryption key pair for the
// given kid.  If a private key already exists in the cache (i.e. the request-
// object endpoint was already called for this session) the cached key is
// reused so that the wallet's encrypted response can still be decrypted.
// Otherwise a fresh P-256 key pair is generated, the private key is cached,
// and both private and public JWKs are returned.
func (c *Client) EphemeralEncryptionKey(ctx context.Context, kid string) (jwk.Key, jwk.Key, error) {
	// Return the existing key pair when available to avoid overwriting the
	// private key on repeated request-object fetches (wallet retries, etc.).
	if existing, ok := c.cacheService.EphemeralEncryptionKey.Get(ctx, kid); ok {
		publicJWK, err := existing.PublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive public key from cached ephemeral key: %w", err)
		}
		if err := publicJWK.Set("use", "enc"); err != nil {
			return nil, nil, err
		}
		return existing, publicJWK, nil
	}

	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privateJWK, err := jwk.Import(privKey)
	if err != nil {
		return nil, nil, err
	}
	if err := privateJWK.Set("kid", kid); err != nil {
		return nil, nil, err
	}

	c.cacheService.EphemeralEncryptionKey.Set(ctx, kid, privateJWK)

	pub := privKey.Public()

	publicJWK, err := jwk.Import(pub)
	if err != nil {
		return nil, nil, err
	}

	if err := publicJWK.Set("use", "enc"); err != nil {
		return nil, nil, err
	}

	if err := publicJWK.Set("kid", kid); err != nil {
		return nil, nil, err
	}

	return privateJWK, publicJWK, nil
}

type CredentialOfferLookupMetadata struct {
	// CredentialTypes use scope as key
	CredentialTypes map[string]CredentialOfferTypeData `json:"credential_types"`

	// Wallet use name in config as key and description as value
	Wallets map[string]string `json:"wallets"`
}
type CredentialOfferTypeData struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CreateCredentialOfferLookupMetadata provides data for UI /offer, credential_offer selection
func (c *Client) CreateCredentialOfferLookupMetadata(ctx context.Context) error {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	c.log.Info("Running CreateCredentialOfferLookupMetadata")

	credentialTypes := map[string]CredentialOfferTypeData{}

	for scope, credential := range c.cfg.Common.CredentialMetadata {
		if vctm := credential.GetVCTM(); vctm != nil {
			credentialTypes[scope] = CredentialOfferTypeData{
				Name:        vctm.Name,
				Description: vctm.Description,
			}
			continue
		}

		if mddl := credential.GetMDDL(); mddl != nil {
			var name, description string
			if len(mddl.Display) > 0 {
				name = mddl.Display[0].Name
				description = mddl.Display[0].Description
			}
			credentialTypes[scope] = CredentialOfferTypeData{
				Name:        name,
				Description: description,
			}
			continue
		}

		c.log.Warn("credential constructor has neither VCTM nor MDDL; failing CreateCredentialOfferLookupMetadata", "scope", scope)
		return fmt.Errorf("credential constructor for scope %q has no VCTM or MDDL configured", scope)
	}

	wallets := map[string]string{}
	for key, wallet := range c.cfg.APIGW.Delivery.CredentialOffers.Wallets {
		wallets[key] = wallet.Label
	}

	c.CredentialOfferLookupMetadata = &CredentialOfferLookupMetadata{
		CredentialTypes: credentialTypes,
		Wallets:         wallets,
	}

	return nil
}
