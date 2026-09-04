package model

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
)

// RegistrationCertificate configures the EUDI registration certificate (WRPRC, ETSI TS 119 475) a verifier or a credential issuer presents to wallets.
//
// vc does not issue these. A national Registrar in the eIDAS ecosystem
// issues a WRPRC out of band, attesting what the party is registered to do;
// this configuration points at the resulting file.
//
// The same document travels in both directions, which is why one type serves
// both:
//
//   - a verifier conveys it in the OpenID4VP verifier_info request
//     parameter, attesting what it is registered to request;
//   - a credential issuer conveys it in the OpenID4VCI issuer_info metadata
//     parameter, attesting what it is registered to provide.
//
// Either way it informs the wallet's consent dialog and policy checks.
type RegistrationCertificate struct {
	// FilePath is the path to the Registrar-issued WRPRC, a compact JWT with
	// media type "rc-wrp+jwt".
	FilePath string `yaml:"file_path,omitempty" doc_example:"\"/etc/vc/registration-certificate.jwt\""`
	// Format is the format identifier advertised alongside the certificate
	// in the verifier_info parameter. Defaults to "rc-wrp+jwt"; override
	// only for an ecosystem that has profiled a different identifier for
	// the same document.
	Format string `yaml:"format,omitempty" doc_example:"\"rc-wrp+jwt\""`
	// TrustedRootsPath optionally points at a PEM bundle of the Registrar's
	// root certificates. When set, the certificate's own x5c chain is
	// evaluated against it at startup. When unset, the document is still
	// signature-checked and parsed, but nothing establishes that its issuer
	// is a Registrar we accept.
	//
	// The ARF RPRC_16 binding needs both this and an access certificate:
	// it compares the two documents' organisation identifiers, so it is
	// skipped when key_config supplies no certificate chain to compare
	// against.
	TrustedRootsPath string `yaml:"trusted_roots_path,omitempty"`
	// Revocation configures checking this certificate against the Token
	// Status List named in its own status claim. A WRPRC that carries no
	// status reference cannot be checked at all, which reads as
	// "could not determine" rather than as "not revoked".
	Revocation *RevocationCheck `yaml:"revocation,omitempty"`
}

// DefaultRegistrationCertificateFormat is the verifier_info format
// identifier for a WRPRC, matching its JWT media type.
const DefaultRegistrationCertificateFormat = rpcert.WRPRCTyp

// wrprcSigningAlgorithms are the JWS algorithms accepted on a registration
// certificate. Listed explicitly so "none" and the RSA-PKCS1 family can
// never be negotiated by an attacker-supplied header.
var wrprcSigningAlgorithms = []string{
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
	"EdDSA",
}

// WRPRCClaims is the registration-certificate payload reduced to the fields
// vc acts on.
//
// Validating a signed object has three steps - verify the signature, extract
// the trust information, evaluate it - and vc owns the first and third:
// verifyWRPRCSignature and evaluateWRPRCChain below, plus the ARF RPRC_16
// binding. The second is delegated to go-trust's rpcert.ParseWRPRCClaims,
// which decodes the wire format and nothing else.
//
// It was originally implemented here, because tolerating what Registrars
// actually emit needed somewhere to live and go-trust had no parser. That
// decoder has since been upstreamed along with the German sandbox fixture
// that motivated it, so the tolerance is shared rather than duplicated - see
// extractWRPRCClaims.
type WRPRCClaims struct {
	// SubjectID is the semantic organisation identifier, e.g.
	// "NTRDE-BD7070256AF93987". It is what binds this document to an access
	// certificate.
	SubjectID string
	// LegalName is the registered legal name of the Relying Party.
	LegalName string
	// TradeName is the user-facing name, from the `name` claim.
	TradeName string
	// Country is the ISO 3166-1 code where the RP is established.
	Country string
	// EntitlementURIs are the Annex A role entitlements the Registrar granted.
	EntitlementURIs []string
	// AllowedAttributes are the top-level claim names this RP is registered
	// to request, flattened from the DCQL credential queries. Used for
	// over-request detection.
	AllowedAttributes []string
	// Purpose holds the multi-language purpose descriptions shown to users.
	Purpose []WRPRCLocalizedText
	// PrivacyPolicyURI, InfoURI and RegistryURI are display/reference links.
	PrivacyPolicyURI string
	InfoURI          string
	RegistryURI      string
	// StatusListURI and StatusListIndex locate this certificate's entry in
	// the Registrar's Token Status List, which is how a WRPRC is revoked.
	// Empty when the Registrar issued no status reference, in which case the
	// certificate cannot be checked for revocation at all.
	StatusListURI   string
	StatusListIndex int
}

// StatusReference returns the certificate's Token Status List entry, and
// whether it carried one.
//
// A WRPRC without a status reference is not revocable, which a caller must
// treat as "could not determine" rather than as "not revoked".
func (c *WRPRCClaims) StatusReference() (uri string, index int, ok bool) {
	if c == nil || c.StatusListURI == "" {
		return "", 0, false
	}
	return c.StatusListURI, c.StatusListIndex, true
}

// WRPRCLocalizedText is one language variant of a displayable string.
type WRPRCLocalizedText struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// LoadedRegistrationCertificate holds a registration certificate read at
// startup, ready to be attached to outgoing authorization requests.
type LoadedRegistrationCertificate struct {
	// JWT is the compact rc-wrp+jwt exactly as issued by the Registrar.
	JWT string
	// Format is the verifier_info format identifier to advertise.
	Format string
	// Claims is what the Registrar attested, extracted after the signature
	// was verified. Always populated for a successfully loaded certificate.
	Claims *WRPRCClaims
	// TrustEvaluated reports whether the issuing chain was actually checked
	// against configured Registrar roots. False means the document is
	// authentic but nothing establishes that we accept its issuer.
	TrustEvaluated bool
}

// VerifierInfo renders the certificate as OpenID4VP verifier_info entries.
//
// No credential_ids are set: a registration certificate describes the
// Relying Party as a whole rather than any single requested credential, and
// per OpenID4VP an omitted credential_ids means the attestation applies to
// every credential in the request.
func (l *LoadedRegistrationCertificate) VerifierInfo() []openid4vp.VerifierInfo {
	if l == nil || l.JWT == "" {
		return nil
	}
	return []openid4vp.VerifierInfo{{
		Format: l.Format,
		Data:   l.JWT,
	}}
}

// IssuerInfo renders the certificate as OpenID4VCI issuer_info entries.
//
// Same document and same shape as VerifierInfo; only the metadata parameter
// carrying it differs. A credential issuer is a registered wallet-relying
// party in its own right under CIR (EU) 2025/848, so what it presents to a
// wallet is the same registration certificate a verifier presents.
func (l *LoadedRegistrationCertificate) IssuerInfo() []openid4vci.IssuerInfo {
	if l == nil || l.JWT == "" {
		return nil
	}
	return []openid4vci.IssuerInfo{{
		Format: l.Format,
		Data:   l.JWT,
	}}
}

// LoadRegistrationCertificate reads, verifies and extracts the configured
// registration certificate. It returns (nil, nil) when none is configured,
// so a deployment outside an ARF trust framework is unaffected.
//
// The three steps of validating a signed object are kept distinct:
//
//  1. verify the signature against the certificate in the document's own x5c;
//  2. extract the attested claims - the only step delegated, to go-trust's
//     rpcert.ParseWRPRCClaims, which decodes the wire format and decides
//     nothing;
//  3. evaluate whether that issuer is one we trust - the only step that is a
//     trust decision, and it stays here: evaluateWRPRCChain plus the
//     binding check below.
//
// accessCert is the verifier's own access certificate, used in step 3 to
// confirm both documents describe the same organisation (ARF RPRC_16). Pass
// nil when none is loaded; the binding check is then skipped.
func (v *Verifier) LoadRegistrationCertificate(accessCert *x509.Certificate) (*LoadedRegistrationCertificate, error) {
	return v.RegistrationCertificate.Load(accessCert)
}

// Load reads, verifies and extracts the certificate this configuration points
// at, following the same three steps described on
// Verifier.LoadRegistrationCertificate.
//
// It hangs off the configuration rather than off a service because the
// document says the same thing wherever it is presented: a verifier conveys
// it in verifier_info, a credential issuer in issuer_info, and neither
// changes how it is validated.
func (cfg *RegistrationCertificate) Load(accessCert *x509.Certificate) (*LoadedRegistrationCertificate, error) {
	if cfg == nil || cfg.FilePath == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(cfg.FilePath)
	if err != nil {
		return nil, fmt.Errorf("reading registration certificate %q: %w", cfg.FilePath, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil, fmt.Errorf("registration certificate %q is empty", cfg.FilePath)
	}

	// Step 0 - shape. A path pointing at some other PEM or JSON file should
	// fail here rather than by being handed to wallets as an unusable
	// attestation.
	chain, err := wrprcChain(token)
	if err != nil {
		return nil, fmt.Errorf("registration certificate %q: %w", cfg.FilePath, err)
	}

	// Step 1 - signature, against the leaf of the document's own x5c. This
	// proves only that the payload is the one the holder of that certificate
	// signed; whether that certificate is acceptable is step 3.
	if err := verifyWRPRCSignature(token, chain[0]); err != nil {
		return nil, fmt.Errorf("registration certificate %q: %w", cfg.FilePath, err)
	}

	// Step 2 - extract.
	claims, err := extractWRPRCClaims(token)
	if err != nil {
		return nil, fmt.Errorf("registration certificate %q: %w", cfg.FilePath, err)
	}

	loaded := &LoadedRegistrationCertificate{
		JWT:    token,
		Format: cfg.Format,
		Claims: claims,
	}
	if loaded.Format == "" {
		loaded.Format = DefaultRegistrationCertificateFormat
	}

	if cfg.TrustedRootsPath == "" {
		return loaded, nil
	}

	// Step 3 - evaluate. Does this chain lead to a Registrar we accept, and
	// does the document describe the same organisation as our access
	// certificate?
	roots, err := loadCertPool(cfg.TrustedRootsPath)
	if err != nil {
		return nil, fmt.Errorf("registration certificate trusted roots %q: %w", cfg.TrustedRootsPath, err)
	}
	if err := evaluateWRPRCChain(chain, roots); err != nil {
		return nil, fmt.Errorf("registration certificate %q: %w", cfg.FilePath, err)
	}
	loaded.TrustEvaluated = true

	// ARF RPRC_16: a mismatched pair would let a wallet attribute one
	// organisation's entitlements to another.
	if accessCert != nil {
		orgID, err := wrpacOrganizationIdentifier(accessCert)
		if err != nil {
			return nil, fmt.Errorf("registration certificate: reading access certificate organisation identifier: %w", err)
		}
		// go-trust's binding check treats an empty value on either side as
		// "not present" and returns nil. That is right for its WRPRC-only
		// callers, and wrong here: an access certificate was supplied, so
		// RPRC_16 is meant to be enforced, and an absent identifier means
		// the binding cannot be checked at all. Letting that read as a pass
		// would leave a certificate that simply omits the field bypassing
		// the check while appearing to satisfy it.
		if orgID == "" {
			return nil, fmt.Errorf("registration certificate: cannot enforce the access-certificate binding (ARF RPRC_16) because the access certificate carries no organisation identifier")
		}
		if claims.SubjectID == "" {
			return nil, fmt.Errorf("registration certificate: cannot enforce the access-certificate binding (ARF RPRC_16) because the certificate's sub claim carries no identifier")
		}
		if err := rpcert.CheckWRPACWRPRCBinding(orgID, &rpcert.RPEntitlements{
			Subject: rpcert.WRPRCSubject{ID: claims.SubjectID},
		}); err != nil {
			return nil, fmt.Errorf("registration certificate does not match the access certificate: %w", err)
		}
	}

	return loaded, nil
}

// wrprcChain checks the token is a compact JWT carrying the WRPRC media type
// and returns the certificate chain from its x5c header.
func wrprcChain(token string) ([]*x509.Certificate, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWT: expected 3 dot-separated parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	var header struct {
		Typ string `json:"typ"`
		X5C any    `json:"x5c"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	// Exact match, matching how pkg/trust compares the attestation typ.
	// JWT typ is nominally a media type and so case-insensitive, but every
	// Registrar emits the lowercase form and the codebase compares these
	// exactly elsewhere; one rule is worth more than the latitude.
	if header.Typ != rpcert.WRPRCTyp {
		return nil, fmt.Errorf("unexpected JWT typ %q, want %q", header.Typ, rpcert.WRPRCTyp)
	}
	if header.X5C == nil {
		return nil, fmt.Errorf("JWT header has no x5c certificate chain to verify against")
	}
	chain, err := jose.ParseX5CHeader(header.X5C)
	if err != nil {
		return nil, fmt.Errorf("parsing x5c header: %w", err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("x5c header contains no certificates")
	}
	return chain, nil
}

// verifyWRPRCSignature verifies the compact JWS against leaf's public key,
// restricted to the algorithms in wrprcSigningAlgorithms.
func verifyWRPRCSignature(token string, leaf *x509.Certificate) error {
	parser := jwt.NewParser(
		jwt.WithValidMethods(wrprcSigningAlgorithms),
		// A registration certificate need not carry exp/iat, and its
		// lifetime is governed by the Registrar's own status list rather
		// than JWT expiry, so claim-time validation is not applied here.
		jwt.WithoutClaimsValidation(),
	)
	if _, err := parser.Parse(token, func(*jwt.Token) (any, error) {
		return leaf.PublicKey, nil
	}); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// extractWRPRCClaims decodes the payload into the fields we act on.
//
// The wire format lives in go-trust's rpcert.ParseWRPRCClaims, which is
// tolerant of both TS 119 475 v1.1.1 and v1.2.1 spellings. It used to be
// duplicated here; keeping one implementation means a Registrar quirk found
// by any consumer is fixed for all of them, rather than in whichever copy
// happened to hit it.
//
// Note what this deliberately is not: rpcert.ParseWRPRCClaims performs no
// cryptographic verification whatsoever. The signature is verified in
// verifyWRPRCSignature and the chain in evaluateWRPRCChain - steps one and
// three, which stay here because they are the caller's to own.
func extractWRPRCClaims(token string) (*WRPRCClaims, error) {
	payload, err := rpcert.ParseWRPRCJWTPayload(token)
	if err != nil {
		return nil, err
	}
	ent, err := rpcert.ParseWRPRCClaims(payload)
	if err != nil {
		return nil, err
	}

	claims := &WRPRCClaims{
		SubjectID:         ent.Subject.ID,
		LegalName:         ent.Subject.LegalName,
		TradeName:         ent.TradeName,
		Country:           ent.Country,
		EntitlementURIs:   ent.EntitlementURIs,
		AllowedAttributes: ent.AllowedAttributes,
		PrivacyPolicyURI:  ent.PrivacyPolicyURI,
		InfoURI:           ent.InfoURI,
		RegistryURI:       ent.RegistryURI,
		StatusListURI:     ent.StatusListURI,
		StatusListIndex:   ent.StatusListIndex,
	}
	for _, p := range ent.Purpose {
		claims.Purpose = append(claims.Purpose, WRPRCLocalizedText{Lang: p.Lang, Value: p.Value})
	}
	return claims, nil
}

// evaluateWRPRCChain checks the document's chain leads to a trusted Registrar.
func evaluateWRPRCChain(chain []*x509.Certificate, roots *x509.CertPool) error {
	opts := x509.VerifyOptions{
		Roots: roots,
		// A Registrar's signing certificate commonly carries no EKU, and
		// Go's zero value would otherwise demand serverAuth.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if len(chain) > 1 {
		intermediates := x509.NewCertPool()
		for _, c := range chain[1:] {
			intermediates.AddCert(c)
		}
		opts.Intermediates = intermediates
	}
	if _, err := chain[0].Verify(opts); err != nil {
		return fmt.Errorf("x5c chain does not lead to a configured Registrar root: %w", err)
	}
	return nil
}

// wrpacOrganizationIdentifier pulls the organisation identifier out of an
// access certificate, using the same WRPAC profile mapping a relying party
// would apply, so the binding check compares like with like.
func wrpacOrganizationIdentifier(cert *x509.Certificate) (string, error) {
	identity, err := rpcert.NewWRPACProfile().ExtractIdentity(cert)
	if err != nil {
		return "", err
	}
	id, _ := identity["organization_identifier"].(string)
	return id, nil
}

// loadCertPool reads a PEM bundle into an x509.CertPool.
func loadCertPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no PEM certificates found in %q", path)
	}
	return pool, nil
}
