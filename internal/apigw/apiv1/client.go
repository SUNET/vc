package apiv1

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
	"vc/internal/apigw/db"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/cache"
	"vc/pkg/grpchelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
	"vc/pkg/pki"
	"vc/pkg/trace"

	"github.com/jellydator/ttlcache/v3"
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
	usersStore           db.UsersStore
	credentialOfferStore db.CredentialOfferStore
	datastoreStore       db.DatastoreStore

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
	authContextCache            *cache.AuthContextCache
	ephemeralEncryptionKeyCache *ttlcache.Cache[string, jwk.Key]
	svgTemplateCache            *ttlcache.Cache[string, SVGTemplateReply]
	documentCache               *ttlcache.Cache[string, map[string]*model.CompleteDocument]
	dpopJTICache                *ttlcache.Cache[string, bool]
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, tracer *trace.Tracer, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:                           cfg,
		db:                            db,
		authContextCache:              cache.NewAuthContextCache(10 * time.Minute), // Short-lived authorization contexts
		usersStore:                    db.VCUsersColl,
		credentialOfferStore:          db.VCCredentialOfferColl,
		datastoreStore:                db.VCDatastoreColl,
		log:                           log.New("apiv1"),
		tracer:                        tracer,
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
		ephemeralEncryptionKeyCache:   ttlcache.New(ttlcache.WithTTL[string, jwk.Key](10 * time.Minute)),
		svgTemplateCache:              ttlcache.New(ttlcache.WithTTL[string, SVGTemplateReply](2 * time.Hour)),
		documentCache:                 ttlcache.New(ttlcache.WithTTL[string, map[string]*model.CompleteDocument](5 * time.Minute)),
		dpopJTICache:                  ttlcache.New(ttlcache.WithTTL[string, bool](5 * time.Minute)),
	}

	go c.dpopJTICache.Start()

	// Start the ephemeral encryption key cache
	go c.ephemeralEncryptionKeyCache.Start()

	// Delete expired cache items automatically
	go c.svgTemplateCache.Start()

	go c.documentCache.Start()

	var err error
	// CRITICAL: Load VCTM data first - issuer metadata generation depends on it
	// All credential constructors must load successfully for the service to start properly
	var loadErrors []error
	for scope, credentialInfo := range cfg.CredentialConstructor {
		if err := credentialInfo.LoadVCTMetadata(ctx, scope); err != nil {
			c.log.Error(err, "Failed to load VCTM for credential constructor", "scope", scope, "vct", credentialInfo.VCT, "vctm_file", credentialInfo.VCTMFilePath)
			loadErrors = append(loadErrors, fmt.Errorf("scope %s (vct=%s, file=%s): %w", scope, credentialInfo.VCT, credentialInfo.VCTMFilePath, err))
			continue
		}

		credentialInfo.Attributes = credentialInfo.VCTM.Attributes()
		c.log.Info("Successfully loaded VCTM for credential constructor", "scope", scope, "vct", credentialInfo.VCT)
	}

	// If any credential constructor failed to load, fail fast with detailed error information
	// This ensures the service doesn't start with incomplete credential configurations
	if len(loadErrors) > 0 {
		// Log summary before returning combined error
		c.log.Error(nil, "Failed to load one or more credential constructors", "failed_count", len(loadErrors), "total_count", len(cfg.CredentialConstructor))
		// Return a combined error that preserves all failure information
		return nil, errors.Join(loadErrors...)
	}

	// Generate issuer metadata at runtime (depends on credential constructors being loaded)
	// Unsigned metadata will be signed on-demand in the handler for freshness
	c.issuerMetadata, err = c.cfg.APIGW.IssuerMetadata.Generate(ctx, c.cfg.APIGW.PublicURL, cfg.CredentialConstructor)
	if err != nil {
		return nil, fmt.Errorf("failed to generate issuer metadata: %w", err)
	}

	// Load OAuth2 metadata from configuration (unsigned, will be signed on-demand if needed)
	c.oauth2Metadata = c.cfg.APIGW.OauthServer.GenerateMetadata(ctx, c.cfg.APIGW.PublicURL)

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

// EphemeralEncryptionKey generates a new ephemeral encryption key pair, return private and public JWKs and KID, or error
func (c *Client) EphemeralEncryptionKey(kid string) (jwk.Key, jwk.Key, error) {
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

	c.ephemeralEncryptionKeyCache.Set(kid, privateJWK, ttlcache.DefaultTTL)

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

	for scope, credential := range c.cfg.CredentialConstructor {
		if err := credential.LoadVCTMetadata(ctx, scope); err != nil {
			continue
		}

		vctm := credential.VCTM

		credentialTypes[scope] = CredentialOfferTypeData{
			Name:        vctm.Name,
			Description: vctm.Description,
		}
	}

	wallets := map[string]string{}
	for key, wallet := range c.cfg.APIGW.CredentialOffers.Wallets {
		wallets[key] = wallet.Label
	}

	c.CredentialOfferLookupMetadata = &CredentialOfferLookupMetadata{
		CredentialTypes: credentialTypes,
		Wallets:         wallets,
	}

	return nil
}
