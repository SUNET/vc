package model

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
)

// RegistrationCertificate configures the EUDI Relying Party registration
// certificate (WRPRC, ETSI TS 119 475) this verifier presents to wallets.
//
// vc does not issue these. A national Registrar in the eIDAS ecosystem
// issues a WRPRC to the Relying Party out of band, attesting what the RP is
// registered to request; this configuration points at the resulting file so
// it can be conveyed to wallets in the OpenID4VP verifier_info request
// parameter, where it informs the wallet's consent dialog and policy checks.
type RegistrationCertificate struct {
	// FilePath is the path to the Registrar-issued WRPRC, a compact JWT with
	// media type "rc-wrp+jwt".
	FilePath string `yaml:"file_path,omitempty" doc_example:"\"/etc/vc/registration-certificate.jwt\""`
	// Format is the verifier_info format identifier advertised alongside the
	// certificate. Defaults to "rc-wrp+jwt"; override only for an ecosystem
	// that has profiled a different identifier for the same document.
	Format string `yaml:"format,omitempty" doc_example:"\"rc-wrp+jwt\""`
	// TrustedRootsPath optionally points at a PEM bundle of the Registrar's
	// root certificates. When set, the WRPRC's own x5c chain is validated
	// against it at startup and its entitlements are checked for consistency
	// with the access certificate. When unset, only the document's structure
	// is checked, since chain validation without trust anchors would be
	// theatre.
	TrustedRootsPath string `yaml:"trusted_roots_path,omitempty"`
}

// DefaultRegistrationCertificateFormat is the verifier_info format
// identifier for a WRPRC, matching its JWT media type.
const DefaultRegistrationCertificateFormat = rpcert.WRPRCTyp

// LoadedRegistrationCertificate holds a registration certificate read at
// startup, ready to be attached to outgoing authorization requests.
type LoadedRegistrationCertificate struct {
	// JWT is the compact rc-wrp+jwt exactly as issued by the Registrar.
	JWT string
	// Format is the verifier_info format identifier to advertise.
	Format string
	// Entitlements is what the Registrar attested, populated only when
	// trusted_roots_path was configured and validation succeeded. It is nil
	// for a structurally-checked-only certificate, so callers must not treat
	// a nil value as "no entitlements".
	Entitlements *rpcert.RPEntitlements
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

// LoadRegistrationCertificate reads and checks the configured registration
// certificate. It returns (nil, nil) when none is configured, so a
// deployment outside an ARF trust framework is unaffected.
//
// accessCert is the verifier's own access certificate, used only to confirm
// the two documents describe the same organisation (ARF RPRC_16). Pass nil
// when none is loaded; the binding check is then skipped.
func (v *Verifier) LoadRegistrationCertificate(accessCert *x509.Certificate) (*LoadedRegistrationCertificate, error) {
	cfg := v.RegistrationCertificate
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

	// Structural check, always: a misconfigured path pointing at some other
	// PEM or JSON file should fail here, at startup, rather than by being
	// handed to wallets as an unparseable attestation.
	if err := checkWRPRCStructure(token); err != nil {
		return nil, fmt.Errorf("registration certificate %q: %w", cfg.FilePath, err)
	}

	loaded := &LoadedRegistrationCertificate{
		JWT:    token,
		Format: cfg.Format,
	}
	if loaded.Format == "" {
		loaded.Format = DefaultRegistrationCertificateFormat
	}

	if cfg.TrustedRootsPath == "" {
		return loaded, nil
	}

	// Full validation: chain the WRPRC's x5c to the Registrar's roots and
	// extract what it attests.
	roots, err := loadCertPool(cfg.TrustedRootsPath)
	if err != nil {
		return nil, fmt.Errorf("registration certificate trusted roots %q: %w", cfg.TrustedRootsPath, err)
	}
	entitlements, err := rpcert.NewJWTRegistrationCertValidator(roots).Validate(context.Background(), []byte(token))
	if err != nil {
		return nil, fmt.Errorf("registration certificate %q failed validation: %w", cfg.FilePath, err)
	}
	loaded.Entitlements = entitlements

	// ARF RPRC_16: the registration certificate must describe the same
	// organisation as the access certificate. Presenting a mismatched pair
	// would let a wallet attribute one organisation's entitlements to
	// another.
	if accessCert != nil {
		orgID, err := wrpacOrganizationIdentifier(accessCert)
		if err != nil {
			return nil, fmt.Errorf("registration certificate: reading access certificate organisation identifier: %w", err)
		}
		if err := rpcert.CheckWRPACWRPRCBinding(orgID, entitlements); err != nil {
			return nil, fmt.Errorf("registration certificate does not match the access certificate: %w", err)
		}
	}

	return loaded, nil
}

// checkWRPRCStructure verifies the token is a compact JWT carrying the
// WRPRC media type, without needing trust anchors.
func checkWRPRCStructure(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a compact JWT: expected 3 dot-separated parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decoding JWT header: %w", err)
	}
	var header struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("parsing JWT header: %w", err)
	}
	if !strings.EqualFold(header.Typ, rpcert.WRPRCTyp) {
		return fmt.Errorf("unexpected JWT typ %q, want %q", header.Typ, rpcert.WRPRCTyp)
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
