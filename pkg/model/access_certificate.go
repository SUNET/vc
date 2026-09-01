package model

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/pki"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
)

// AccessCertificate configures validation of the verifier's own wallet-facing certificate as an EUDI Relying Party access certificate (WRPAC, ETSI TS 119 411-8).
//
// This validates the certificate the verifier already signs request objects
// with - it does not introduce a second certificate. Deployments not
// participating in an ARF trust framework can leave it disabled and are
// unaffected.
type AccessCertificate struct {
	// Validate enforces the WRPAC certificate profile at startup: keyUsage
	// must include nonRepudiation (contentCommitment), subjectAltName must
	// carry contact information (URI or email), and certificatePolicies must
	// contain a WRPAC policy OID. Startup fails when the certificate does
	// not conform.
	Validate bool `yaml:"validate,omitempty"`
	// AllowedPolicyOIDs optionally narrows which WRPAC certificate policy
	// OIDs are accepted, for a deployment that must assert a specific
	// assurance level (e.g. only the qualified policies). When empty, all
	// four TS 119 411-8 WRPAC policy OIDs are accepted.
	AllowedPolicyOIDs []string `yaml:"allowed_policy_oids,omitempty" doc_example:"[\"0.4.0.194118.1.3\",\"0.4.0.194118.1.4\"]"`
}

// ErrNoAccessCertificate reports that WRPAC validation was requested but no
// certificate was loaded to validate.
var ErrNoAccessCertificate = errors.New("access_certificate.validate is set but no signing certificate was loaded from key_config")

// ValidateAccessCertificate checks the verifier's own signing certificate
// against the WRPAC profile and its own validity window.
//
// It is deliberately offline: every check reads the certificate's own
// attributes, so this is profile conformance, not a trust decision. Deciding
// whether some *other* party's certificate is trusted belongs to the PDP.
//
// now is injected so the validity-window check is testable; callers pass
// time.Now().
func (v *Verifier) ValidateAccessCertificate(leaf *x509.Certificate, now time.Time) error {
	return v.AccessCertificate.ValidateCertificate(leaf, now)
}

// ValidateCertificate checks a certificate against the WRPAC profile and its
// own validity window.
//
// This is the shared implementation behind both the verifier's and the
// issuer's startup check. Under CIR (EU) 2025/848 a PID or attestation
// provider is a registered wallet-relying party in its own right, so the
// same profile governs the certificate an issuer presents - one rule, not
// two copies that drift.
//
// A nil receiver, or one with Validate unset, passes: a deployment outside
// an ARF trust framework is unaffected.
func (a *AccessCertificate) ValidateCertificate(leaf *x509.Certificate, now time.Time) error {
	if a == nil || !a.Validate {
		return nil
	}
	if leaf == nil {
		return ErrNoAccessCertificate
	}

	// Validity window first: an expired certificate fails every downstream
	// check anyway, and saying so plainly beats a profile error that sends
	// the reader looking at keyUsage.
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("access certificate is not valid until %s (now %s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("access certificate expired at %s (now %s)",
			leaf.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}

	// WRPAC profile conformance: keyUsage, SAN contact info, policy OID.
	if err := rpcert.NewWRPACProfile().ValidateCredential(leaf); err != nil {
		return fmt.Errorf("access certificate does not conform to the WRPAC profile: %w", err)
	}

	// Optional narrowing to specific policy OIDs. The profile check above
	// already proved at least one WRPAC OID is present; this additionally
	// requires it to be one the deployment accepts.
	if len(a.AllowedPolicyOIDs) > 0 {
		present := rpcert.CertPolicyOIDStrings(leaf)
		if !containsAny(present, a.AllowedPolicyOIDs) {
			return fmt.Errorf("access certificate policy OIDs %v include none of the allowed %v",
				present, a.AllowedPolicyOIDs)
		}
	}

	return nil
}

// containsAny reports whether any element of got appears in want.
func containsAny(got, want []string) bool {
	allowed := make(map[string]bool, len(want))
	for _, w := range want {
		allowed[w] = true
	}
	for _, g := range got {
		if allowed[g] {
			return true
		}
	}
	return false
}

// CheckPublicURLMatchesCertificate reports whether the host in PublicURL
// appears in the certificate's DNS SANs.
//
// This only matters for client_id_scheme "x509_san_dns", where the client_id
// is that host: a wallet resolves it against the certificate's DNS SANs, so a
// mismatch means every request is rejected. "x509_hash" pins the certificate
// bytes instead and "did" does not involve the certificate at all, so both
// are reported as matching.
//
// It returns a descriptive error rather than a bool so the caller can log or
// fail with the specific mismatch. Callers treat this as a warning by default
// - an existing deployment may have been running this way - and only as fatal
// when access_certificate.validate is set.
func (v *Verifier) CheckPublicURLMatchesCertificate(leaf *x509.Certificate) error {
	if v.ClientIDScheme != "x509_san_dns" || leaf == nil {
		return nil
	}
	// Check the value we actually advertise, not a separately-derived host.
	// VerifierClientID builds the identifier from PublicURL's Host, which
	// keeps any port; deriving Hostname() here instead would strip it and
	// report a match for a PublicURL that no wallet can ever resolve - a
	// port makes the value not a DNS name, so it cannot appear in a SAN.
	// Asking the emitter removes the chance of the two drifting.
	clientID, err := v.VerifierClientID(leaf)
	if err != nil {
		return err
	}
	scheme, host, ok := registry.ParseClientIDScheme(clientID)
	if !ok || scheme != registry.ClientIDSchemeX509SANDNS {
		return fmt.Errorf("expected an x509_san_dns client_id, got %q", clientID)
	}
	if host == "" {
		return fmt.Errorf("PublicURL %q has no host component", v.PublicURL)
	}
	// Reuse the wallet-side matcher so this agrees with what a relying
	// party actually checks, wildcards included, rather than a separate
	// string comparison that could drift from it.
	if !registry.DNSSANMatches(host, leaf.DNSNames) {
		return fmt.Errorf("client_id_scheme is \"x509_san_dns\" but the advertised client_id host %q is not present in the certificate's DNS SANs %v: wallets will reject every request object",
			host, leaf.DNSNames)
	}
	return nil
}

// IssuerAccessCertificate configures the EUDI Relying Party access certificate (WRPAC, ETSI TS 119 411-8) the issuer presents to wallets, and optionally gives it its own key.
//
// Under CIR (EU) 2025/848 a PID or attestation provider is a registered
// wallet-relying party in its own right, so the certificate that
// authenticates the issuer to a wallet is a WRPAC, governed by the same
// profile the verifier uses.
//
// The access certificate is kept separate from Issuer.KeyConfig on purpose.
// The credential key is published in /jwks and signs credentials; an mdoc
// document-signer certificate chains to an IACA under an entirely different
// profile; and the two have independent rotation lifecycles. Conflating them
// means a WRPAC rotation forces a credential-key rotation.
//
// When KeyConfig is unset the issuer falls back to signing metadata with the
// credential key, logging a warning. That keeps an existing single-key
// deployment booting across an upgrade rather than failing on start.
type IssuerAccessCertificate struct {
	// Validate enforces the WRPAC certificate profile at startup: keyUsage
	// must include nonRepudiation (contentCommitment), subjectAltName must
	// carry contact information (URI or email), and certificatePolicies must
	// contain a WRPAC policy OID. Startup fails when the certificate does
	// not conform.
	Validate bool `yaml:"validate,omitempty"`
	// AllowedPolicyOIDs optionally narrows which WRPAC certificate policy
	// OIDs are accepted, for a deployment that must assert a specific
	// assurance level. When empty, all four TS 119 411-8 WRPAC policy OIDs
	// are accepted.
	AllowedPolicyOIDs []string `yaml:"allowed_policy_oids,omitempty" doc_example:"[\"0.4.0.194118.1.3\",\"0.4.0.194118.1.4\"]"`
	// KeyConfig is the signing key and certificate chain for the access
	// certificate. When set, issuer metadata is signed with this key and
	// the chain is advertised in the JWT's x5c header; credentials continue
	// to be signed with Issuer.KeyConfig.
	KeyConfig *pki.KeyConfig `yaml:"key_config,omitempty" validate:"omitempty"`
}

// profile returns the shared profile-validation rule for this configuration.
//
// The two knobs are declared on IssuerAccessCertificate rather than embedded
// from AccessCertificate because the configuration-reference generator does
// not follow yaml-inline embedded structs: embedding left validate and
// allowed_policy_oids working but undocumented. The rule itself still lives
// in one place, which is what matters.
func (i *IssuerAccessCertificate) profile() *AccessCertificate {
	if i == nil {
		return nil
	}
	return &AccessCertificate{Validate: i.Validate, AllowedPolicyOIDs: i.AllowedPolicyOIDs}
}

// ValidateAccessCertificate checks the certificate the issuer signs metadata
// with against the WRPAC profile.
//
// now is injected so the validity-window check is testable; callers pass
// time.Now().
func (i *Issuer) ValidateAccessCertificate(leaf *x509.Certificate, now time.Time) error {
	if i == nil || i.AccessCertificate == nil {
		return nil
	}
	return i.AccessCertificate.profile().ValidateCertificate(leaf, now)
}

// AccessCertificateKeyConfig returns the access certificate's own key
// configuration, or nil when the issuer has not been given one.
//
// A nil result is the signal to fall back to the credential key, which is a
// degraded but supported configuration - see IssuerAccessCertificate.
func (i *Issuer) AccessCertificateKeyConfig() *pki.KeyConfig {
	if i == nil || i.AccessCertificate == nil {
		return nil
	}
	return i.AccessCertificate.KeyConfig
}
