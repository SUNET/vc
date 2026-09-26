package model

import (
	"time"

	"github.com/SUNET/vc/pkg/pki"
)

// StatusServiceConfig enables offloading credential revocation status to an
// external service implementing draft-ietf-oauth-status-list-21 (e.g.
// github.com/sirosfoundation/siros-status-service), reached over its issuer
// ingestion API (POST /allocate, PATCH /status/{listID}/{idx}) fronted by
// its own OAuth2 Authorization Server (POST /token).
//
// The whole feature is a no-op until IngestionURL is set - requirement #1
// ("turned on when an ingestion API endpoint is provided"). Nothing about
// an existing deployment's behaviour changes by this config field merely
// existing; vc's own built-in Token Status List (Issuer.RegistryClient)
// keeps working exactly as before, configured or not, with or without this.
//
// See pkg/statusserviceclient's package doc for the pool, retry, and
// degraded-mode design this configures.
type StatusServiceConfig struct {
	// IngestionURL is the base URL of the status service's issuer-facing
	// ingestion API. Setting this is what turns the feature on; every
	// other field here is tuning. In a sharded deployment this is
	// typically the ingress-router's public URL (see siros-status-
	// service's docs/design.md §15), which fronts every shard behind one
	// address.
	IngestionURL string `yaml:"ingestion_url" validate:"omitempty,url" doc_example:"\"https://status.siros.org\""`
	// ASURL is the base URL of the status service's Authorization Server;
	// POST {ASURL}/token is where client-assertion token requests go.
	// Required whenever IngestionURL is set.
	ASURL string `yaml:"as_url" validate:"omitempty,url" doc_example:"\"https://status-as.siros.org\""`
	// IssuerID is this issuer's self-asserted identity, sent as both `iss`
	// and `sub` in the RFC 7523 client assertion. The status service has
	// no separate registration step - this string plus KeyConfig's public
	// key together *are* the identity a trust decision is made about, so
	// it should be a stable value this issuer is willing to be known by
	// (a URL is a natural, and the safe default below reuses one already
	// serving that role). Defaults to Issuer.IssuerURL when empty.
	IssuerID string `yaml:"issuer_id" validate:"omitempty" doc_example:"\"https://issuer.sunet.se\""`
	// KeyConfig is the EC (P-256) key pair used to sign the RFC 7523
	// client assertion. Defaults to Issuer.KeyConfig - this issuer's own
	// credential-signing key - requirement #2 ("default to the issuer
	// signing key").
	//
	// An HSM-backed (PKCS#11) key is fine, here or as the default. The
	// assertion proves possession of the key by signing with it, which is
	// what the device does; the private half never needs to be readable.
	// Signing goes through pkg/jose.MakeJWT and a pki.Signer, the same path
	// every other JWT in this repository takes.
	//
	// The requirement is ES256 on P-256, because that is what the status
	// service's AS verifies - a non-EC key (e.g. RSA) cannot produce it.
	// Startup fails with an error naming this field when the resolved key
	// cannot, rather than silently disabling the feature.
	KeyConfig *pki.KeyConfig `yaml:"key_config,omitempty" validate:"omitempty"`
	// PoolSize is how many pre-allocated (list_url, index) pairs this
	// process keeps ready in memory so credential issuance is never
	// blocked on a synchronous round trip to the status service -
	// requirement #3 ("pool-based"). Default 50.
	PoolSize int `yaml:"pool_size" default:"50"`
	// PoolLowWaterMark is the pool size, at or below which a background
	// refill triggers. Zero (the default) means PoolSize/4, with a
	// minimum of 5.
	PoolLowWaterMark int `yaml:"pool_low_water_mark"`
	// AllocateExpiry, when non-zero, is sent as POST /allocate's optional
	// `exp` (now + this duration). Left at zero (the default), `exp` is
	// omitted from the request entirely, which asks the status service for
	// exactly its own configured maximum lifetime. That is the right
	// default here specifically because pool entries are allocated well
	// before any specific credential exists to allocate them for (that is
	// the point of the pool) - at refill time this issuer does not yet
	// know any individual credential's real intended expiry, so it cannot
	// pass a more specific value even if it wanted to.
	AllocateExpiry time.Duration `yaml:"allocate_expiry"`
	//
	// IMPORTANT: omission is not a promise that the entry outlives the
	// credential. The service answers with now + its own MAX_EXPIRY, fixed
	// at allocation time, and a pooled entry has already been sitting here
	// before any credential uses it. An issuer minting 365-day credentials
	// against a service whose maximum is shorter hands out credentials that
	// outlive their status entry and become uncheckable near the end of
	// their life. Set this to cover the longest credential lifetime plus the
	// pool's lead time when the service's maximum is not comfortably larger;
	// entries that come back already inside the client's expiry skew are
	// refused rather than issued (see statusserviceclient's Take).
	// DegradedMode controls what happens when the pool is empty AND a
	// bounded synchronous allocation attempt also fails - i.e. the status
	// service is unreachable or erroring at the exact moment a credential
	// is being issued - requirement #4's degraded-mode decision:
	//   - "proceed" (default): issue the credential without a status
	//     claim. It is then unrevokable via this mechanism but otherwise
	//     perfectly valid; this is a graceful-degradation-of-a-secondary-
	//     property choice, in line with how MakeVC20 already treats its
	//     own (built-in) status list allocation as best-effort.
	//   - "fail": fail the credential issuance request outright, trading
	//     availability for the guarantee that no credential using this
	//     status service is ever issued unrevokable.
	// A third mode - block until the status service recovers - is
	// deliberately not offered: it would turn a status-service outage into
	// an outage of this issuer for every credential type it issues, which
	// is worse than either alternative above and defeats the purpose of
	// the pool (never blocking issuance) it would come attached to.
	DegradedMode string `yaml:"degraded_mode" default:"proceed" validate:"omitempty,oneof=proceed fail"`
}
