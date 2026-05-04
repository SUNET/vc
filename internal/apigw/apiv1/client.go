package apiv1

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/grpchelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

//	@title		Datastore API
//	@version	2.8
//	@BasePath	/api/v1

// Client holds the public api object
type Client struct {
	cfg    *model.Cfg
	db     *db.Service
	log    *logger.Log
	tracer *trace.Tracer

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
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, cacheService *cache.Service, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:                           cfg,
		db:                            db,
		credentialOfferStore:          db.VCCredentialOfferColl,
		datastoreStore:                db.VCDatastoreColl,
		identityMappingStore:          db.VCIdentityMappingsColl,
		log:                           log.New("apiv1"),
		tracer:                        tracer,
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
		cacheService:                  cacheService,
	}

	var err error

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
		vctm := credential.GetVCTM()
		if vctm == nil {
			c.log.Warn("credential constructor has nil VCTM; failing CreateCredentialOfferLookupMetadata", "scope", scope)
			return fmt.Errorf("credential constructor for scope %q has no VCTM configured", scope)
		}

		credentialTypes[scope] = CredentialOfferTypeData{
			Name:        vctm.Name,
			Description: vctm.Description,
		}
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
