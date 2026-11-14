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
	"github.com/SUNET/vc/pkg/status"
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
	// uniqueCommitmentStore keeps one commitment per key value of each unique entry.
	uniqueCommitmentStore db.UniqueCommitmentStore

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
	trustEvaluator             trust.TrustEvaluator
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

	// status is the shared readiness aggregator: local probes + downstream
	// Status RPCs, cached + single-flighted. Configured in New.
	statusAggregator *status.Aggregator

	// authProviderSelector answers which auth provider a scope will
	// actually be served by in this deployment. The browser flow consults
	// it at /authorize; the Authorization Challenge Endpoint consults the
	// same one so the two cannot disagree about whether a scope needs a
	// presentation or a browser.
	authProviderSelector AuthProviderSelector

	// issuanceAuth overrides the issuance-auth pipeline the Authorization
	// Challenge Endpoint feeds. nil everywhere but in tests, where it is
	// the only way to reach the endpoint's own code on a presentation that
	// VERIFIES: everything past decryption - SD-JWT or mdoc verification,
	// issuer trust via the PDP, identity resolution, the datastore lookup -
	// needs a signing authority, a trust deployment and documents, none of
	// which say anything about the wiring between this endpoint and the
	// pipeline.
	//
	// That wiring is what breaks silently: the audience a presentation is
	// bound to, the state it must echo, the mdoc session transcript it was
	// signed over, and whether an authorization code comes back at all.
	// Only the challenge endpoint has one, because only it builds a binding
	// that has no other test - the browser flow's is exercised end to end
	// through /verification/direct_post.
	//
	// See issuanceAuthPipeline.
	issuanceAuth issuanceAuthConsumer
}

// AuthProviderSelector names the auth provider, and the credential source,
// that will serve a scope in this deployment.
//
// A narrow local interface rather than the concrete type: the answer
// depends on which provider services actually started, which is knowledge
// the wiring layer has and this package does not, and declaring only what
// is used keeps it substitutable in tests.
//
// Implemented by *authproviders.Selector.
type AuthProviderSelector interface {
	Select(scope string, ds *model.DataSources) (string, model.CredentialSource, error)
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, cacheService *cache.Service, authProviderSelector AuthProviderSelector, tracer *trace.Tracer, meter *metric.Meter, cfg *model.Cfg, log *logger.Log) (*Client, error) {
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
		uniqueCommitmentStore:         db.UniqueCommitmentColl,
		log:                           log.New("apiv1"),
		tracer:                        tracer,
		vciMetrics:                    vciMetrics,
		CredentialOfferLookupMetadata: &CredentialOfferLookupMetadata{},
		cacheService:                  cacheService,
		authProviderSelector:          authProviderSelector,
	}

	c.warnUnresettableCommitments()

	// Generate issuer metadata at runtime (depends on credential constructors being loaded)
	// Unsigned metadata will be signed on-demand in the handler for freshness
	c.issuerMetadata, err = c.cfg.APIGW.IssuerMetadata.Generate(ctx, c.cfg.APIGW.PublicURL, cfg.Common.CredentialMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to generate issuer metadata: %w", err)
	}

	// Advertise attest_jwt_client_auth only when the evaluator will actually be wired below (needs Enabled + PDPURL).
	walletAttestationAdvertised := cfg.APIGW.Trust.WalletAttestation.Enabled && cfg.APIGW.Trust.PDPURL != ""
	c.oauth2Metadata = c.cfg.APIGW.Delivery.OpenID4VCI.GenerateMetadata(ctx, c.cfg.APIGW.PublicURL, walletAttestationAdvertised, cfg.APIGW.Trust.AllowedSignatureAlgorithms, &c.cfg.APIGW.Delivery.InteractiveAuthorization)

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
	c.trustEvaluator = trustEvaluator

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

	c.statusAggregator = c.buildStatusAggregator()

	c.log.Info("Started")

	return c, nil
}

// EphemeralEncryptionKey returns the ephemeral encryption key pair for the
// given kid, generating and storing one if this is the first caller to ask.
//
// Exactly one key ever exists for a kid, and every caller gets that one.
// The private half is what decrypts the wallet's response, and the public
// half goes into a REQUEST THE SERVER SIGNS - so two callers that each
// generated their own would produce two signed requests, and whichever
// private key ended up in the cache would be unable to decrypt a response
// to the other. Nothing downstream could recover from that: the wallet's
// presentation is correct, the signature verifies, and the ciphertext is
// simply undecryptable.
//
// A plain Get-then-Set could not give that guarantee, and the window is
// not theoretical: issuer-initiated issuance and the request-object
// endpoint both reach here for the same kid, and a wallet retrying a
// request object races itself. SetNX decides the winner atomically, and a
// loser reads the winner's key back rather than keeping its own.
func (c *Client) EphemeralEncryptionKey(ctx context.Context, kid string) (jwk.Key, jwk.Key, error) {
	// Return the existing key pair when available to avoid overwriting the
	// private key on repeated request-object fetches (wallet retries, etc.).
	if existing, ok := c.cacheService.EphemeralEncryptionKey.Get(ctx, kid); ok {
		return ephemeralKeyPair(existing)
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

	stored, err := c.cacheService.EphemeralEncryptionKey.SetNX(ctx, kid, privateJWK)
	if err != nil {
		// Propagated rather than swallowed. A cache that would not take
		// the key is a request this server cannot decrypt the answer to,
		// and signing it anyway produces a flow that fails much later
		// with nothing to point at.
		c.log.Error(err, "failed to store the ephemeral encryption key", "kid", kid)
		return nil, nil, fmt.Errorf("storing the ephemeral encryption key for %q: %w", kid, err)
	}
	if !stored {
		// Another caller got there first. Its key is the one the cache
		// holds and therefore the only one that can decrypt anything, so
		// this caller signs with that rather than with the key it just
		// generated and is about to throw away.
		winner, ok := c.cacheService.EphemeralEncryptionKey.Get(ctx, kid)
		if !ok {
			return nil, nil, fmt.Errorf("the ephemeral encryption key for %q was taken by another caller and is already gone", kid)
		}
		return ephemeralKeyPair(winner)
	}

	return ephemeralKeyPair(privateJWK)
}

// ephemeralKeyPair returns the private key as stored and the public half a
// wallet will accept.
func ephemeralKeyPair(privateJWK jwk.Key) (jwk.Key, jwk.Key, error) {
	publicJWK, err := privateJWK.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive public key from ephemeral key: %w", err)
	}
	if err := publicJWK.Set("use", "enc"); err != nil {
		return nil, nil, err
	}
	// The reference wallet's ClientMetaDataValidator (eudi-lib-jvm-openid4vp-kt)
	// only treats a jwks entry as a viable encryption-key candidate if it has
	// both a non-blank "kid" AND a non-blank "alg" -- entries without "alg"
	// are silently filtered out, so without this the candidate list ends up
	// empty and the wallet rejects the request with InvalidClientMetaData
	// ("No encryption JWKs were advertised").
	if err := publicJWK.Set("alg", "ECDH-ES"); err != nil {
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
