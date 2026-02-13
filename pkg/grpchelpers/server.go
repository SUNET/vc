package grpchelpers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"vc/pkg/model"
)

// NewServerOptions returns gRPC server options with optional TLS/mTLS support.
// If TLS is disabled, returns nil (for insecure server).
// If TLS is enabled without client CA, uses server-only TLS.
// If TLS is enabled with client CA, uses mutual TLS (mTLS) requiring client certificates.
// If AllowedClientFingerprints or AllowedClientDNs is set, adds an interceptor to verify client certs.
func NewServerOptions(cfg model.GRPCServer) ([]grpc.ServerOption, error) {
	if !cfg.TLS.Enabled {
		return nil, nil
	}

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(cfg.TLS.CertFilePath, cfg.TLS.KeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	// If client CA is specified, enable mTLS (mutual TLS)
	if cfg.TLS.ClientCAPath != "" {
		clientCA, err := os.ReadFile(cfg.TLS.ClientCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA certificate: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(clientCA) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caPool
	}

	creds := credentials.NewTLS(tlsConfig)
	opts := []grpc.ServerOption{grpc.Creds(creds)}

	// Add client identity verification interceptor if any allowlist is configured
	allowedFingerprints, allowedDNs := buildClientAllowlists(cfg.TLS)
	if allowedFingerprints != nil || allowedDNs != nil {
		interceptor := clientAuthUnaryInterceptor(allowedFingerprints, allowedDNs)
		streamInterceptor := clientAuthStreamInterceptor(allowedFingerprints, allowedDNs)
		opts = append(opts,
			grpc.UnaryInterceptor(interceptor),
			grpc.StreamInterceptor(streamInterceptor),
		)
	}

	return opts, nil
}

// buildClientAllowlists normalizes the fingerprint and DN allowlists from the TLS config.
// Returns nil maps when the respective allowlist is not configured.
func buildClientAllowlists(tlsCfg model.GRPCTLS) (allowedFingerprints, allowedDNs map[string]string) {
	if len(tlsCfg.AllowedClientFingerprints) > 0 {
		allowedFingerprints = make(map[string]string, len(tlsCfg.AllowedClientFingerprints))
		for fp, name := range tlsCfg.AllowedClientFingerprints {
			allowedFingerprints[normalizeFingerprint(fp)] = name
		}
	}

	if len(tlsCfg.AllowedClientDNs) > 0 {
		allowedDNs = make(map[string]string, len(tlsCfg.AllowedClientDNs))
		for dn, name := range tlsCfg.AllowedClientDNs {
			allowedDNs[canonicalizeDN(dn)] = name
		}
	}

	return allowedFingerprints, allowedDNs
}

// normalizeFingerprint normalizes a fingerprint string for comparison.
// Removes "SHA256:" prefix, colons, spaces, and converts to lowercase.
func normalizeFingerprint(fp string) string {
	fp = strings.ToLower(fp)
	fp = strings.TrimPrefix(fp, "sha256:")
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, " ", "")
	return fp
}

// CertFingerprint calculates the SHA256 fingerprint of a certificate.
// Returns the fingerprint as a lowercase hex string.
func CertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// FormatFingerprint formats a fingerprint with colons for display (e.g., "aa:bb:cc:dd...")
func FormatFingerprint(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 2 {
		end := i + 2
		if end > len(fp) {
			end = len(fp)
		}
		parts = append(parts, fp[i:end])
	}
	return "SHA256:" + strings.Join(parts, ":")
}

// dnAttribute represents a single RDN attribute type-value pair in canonical form.
type dnAttribute struct {
	Type  string // Canonical attribute type (lowercase), e.g., "cn", "o", "c"
	Value string // Normalized attribute value (lowercase, trimmed)
}

// oidShortNames maps well-known OID strings to canonical short attribute type names.
var oidShortNames = map[string]string{
	"2.5.4.3":  "cn",
	"2.5.4.5":  "serialnumber",
	"2.5.4.6":  "c",
	"2.5.4.7":  "l",
	"2.5.4.8":  "st",
	"2.5.4.9":  "street",
	"2.5.4.10": "o",
	"2.5.4.11": "ou",
	"2.5.4.17": "postalcode",
}

// dnTypeAliases maps common attribute type name variants (lowercased) to canonical short names.
// This ensures that regardless of how operators write the DN in config
// (e.g., "CN", "cn", "commonName"), we normalize to the same canonical type.
var dnTypeAliases = map[string]string{
	"cn":                     "cn",
	"commonname":             "cn",
	"c":                      "c",
	"countryname":            "c",
	"o":                      "o",
	"organizationname":       "o",
	"ou":                     "ou",
	"organizationalunitname": "ou",
	"l":                      "l",
	"localityname":           "l",
	"st":                     "st",
	"state":                  "st",
	"stateorprovincename":    "st",
	"street":                 "street",
	"streetaddress":          "street",
	"postalcode":             "postalcode",
	"serialnumber":           "serialnumber",
}

// canonicalizeDN parses a Distinguished Name string and produces a canonical
// representation that is independent of attribute ordering, type name variants,
// case, or whitespace. This makes DN comparison reliable regardless of how
// operators format the DN in configuration.
//
// All of these produce the same canonical output:
//   - "CN=apigw,O=SUNET,C=SE"
//   - "C=SE,O=SUNET,CN=apigw"
//   - "cn=apigw, o=SUNET, c=SE"
//   - "commonName=apigw, organizationName=SUNET, countryName=SE"
func canonicalizeDN(dn string) string {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return ""
	}

	attrs := parseDNString(dn)
	return canonicalFromAttrs(attrs)
}

// certCanonicalDN extracts the Subject DN from a certificate and produces
// the same canonical format used by canonicalizeDN, ensuring that comparison
// between a config string and a certificate DN is always consistent.
func certCanonicalDN(cert *x509.Certificate) string {
	var attrs []dnAttribute
	name := cert.Subject

	if len(name.Names) > 0 {
		// Use Names field which preserves all original attributes and their OIDs.
		for _, atv := range name.Names {
			oid := atv.Type.String()
			typeName, ok := oidShortNames[oid]
			if !ok {
				typeName = oid // Use OID dotted notation as fallback for unknown types
			}
			value := fmt.Sprintf("%v", atv.Value)
			attrs = append(attrs, dnAttribute{
				Type:  typeName,
				Value: strings.ToLower(strings.TrimSpace(value)),
			})
		}
	} else {
		// Fallback: extract from structured fields (when Names is not populated)
		if name.CommonName != "" {
			attrs = append(attrs, dnAttribute{Type: "cn", Value: strings.ToLower(name.CommonName)})
		}
		for _, v := range name.Country {
			attrs = append(attrs, dnAttribute{Type: "c", Value: strings.ToLower(v)})
		}
		for _, v := range name.Organization {
			attrs = append(attrs, dnAttribute{Type: "o", Value: strings.ToLower(v)})
		}
		for _, v := range name.OrganizationalUnit {
			attrs = append(attrs, dnAttribute{Type: "ou", Value: strings.ToLower(v)})
		}
		for _, v := range name.Locality {
			attrs = append(attrs, dnAttribute{Type: "l", Value: strings.ToLower(v)})
		}
		for _, v := range name.Province {
			attrs = append(attrs, dnAttribute{Type: "st", Value: strings.ToLower(v)})
		}
		for _, v := range name.StreetAddress {
			attrs = append(attrs, dnAttribute{Type: "street", Value: strings.ToLower(v)})
		}
		for _, v := range name.PostalCode {
			attrs = append(attrs, dnAttribute{Type: "postalcode", Value: strings.ToLower(v)})
		}
		if name.SerialNumber != "" {
			attrs = append(attrs, dnAttribute{Type: "serialnumber", Value: strings.ToLower(name.SerialNumber)})
		}
	}

	return canonicalFromAttrs(attrs)
}

// parseDNString parses an RFC 2253/4514-style DN string into canonical attribute pairs.
// Handles escaped commas, semicolons as separators, and multi-valued RDNs (using +).
func parseDNString(dn string) []dnAttribute {
	components := splitDNComponents(dn)
	var attrs []dnAttribute

	for _, component := range components {
		component = strings.TrimSpace(component)
		if component == "" {
			continue
		}

		// Handle multi-valued RDNs (e.g., "CN=foo+OU=bar")
		rdnParts := splitUnescaped(component, '+')
		for _, part := range rdnParts {
			part = strings.TrimSpace(part)
			eqIdx := strings.IndexByte(part, '=')
			if eqIdx < 0 {
				continue // Malformed RDN, skip
			}

			attrType := strings.TrimSpace(part[:eqIdx])
			attrValue := strings.TrimSpace(part[eqIdx+1:])

			attrs = append(attrs, dnAttribute{
				Type:  normalizeAttrType(attrType),
				Value: strings.ToLower(attrValue),
			})
		}
	}

	return attrs
}

// splitDNComponents splits a DN string on unescaped commas and semicolons.
func splitDNComponents(dn string) []string {
	var parts []string
	var current strings.Builder
	escaped := false

	for _, r := range dn {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			current.WriteRune(r)
			continue
		}
		if r == ',' || r == ';' {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// splitUnescaped splits a string on unescaped occurrences of the given separator byte.
func splitUnescaped(s string, sep byte) []string {
	var parts []string
	var current strings.Builder
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			current.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			current.WriteByte(c)
			continue
		}
		if c == sep {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(c)
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// normalizeAttrType converts an attribute type name to its canonical short form.
// Handles standard abbreviations (CN, O, OU, etc.), long names (commonName, etc.),
// and OID dotted notation (2.5.4.3, etc.).
func normalizeAttrType(attrType string) string {
	lower := strings.ToLower(strings.TrimSpace(attrType))

	if canonical, ok := dnTypeAliases[lower]; ok {
		return canonical
	}
	if canonical, ok := oidShortNames[lower]; ok {
		return canonical
	}

	return lower
}

// canonicalFromAttrs sorts attributes by type (then value) and builds a canonical DN string.
func canonicalFromAttrs(attrs []dnAttribute) string {
	if len(attrs) == 0 {
		return ""
	}

	sort.Slice(attrs, func(i, j int) bool {
		if attrs[i].Type != attrs[j].Type {
			return attrs[i].Type < attrs[j].Type
		}
		return attrs[i].Value < attrs[j].Value
	})

	var parts []string
	for _, a := range attrs {
		parts = append(parts, a.Type+"="+a.Value)
	}
	return strings.Join(parts, ",")
}

// CertDN returns the Subject Distinguished Name of a certificate as a human-readable string.
// Uses the standard Go x509 String() format. For comparison purposes, use certCanonicalDN instead.
func CertDN(cert *x509.Certificate) string {
	return cert.Subject.String()
}

// clientAuthUnaryInterceptor returns a unary interceptor that verifies client certs
// against both fingerprint and DN allowlists. A client is allowed if it matches EITHER list.
func clientAuthUnaryInterceptor(allowedFingerprints, allowedDNs map[string]string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := verifyClientIdentity(ctx, allowedFingerprints, allowedDNs); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// clientAuthStreamInterceptor returns a stream interceptor that verifies client certs
// against both fingerprint and DN allowlists. A client is allowed if it matches EITHER list.
func clientAuthStreamInterceptor(allowedFingerprints, allowedDNs map[string]string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := verifyClientIdentity(ss.Context(), allowedFingerprints, allowedDNs); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// verifyClientIdentity extracts the client certificate from the context and verifies it
// against fingerprint and/or DN allowlists. The client is allowed if it matches EITHER list.
// This supports both pinned certificates (via fingerprints) and dynamic certificates like
// ACME/Let's Encrypt (via DN matching).
func verifyClientIdentity(ctx context.Context, allowedFingerprints, allowedDNs map[string]string) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer info")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "no TLS info")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "no client certificate")
	}

	clientCert := tlsInfo.State.PeerCertificates[0]

	// Check fingerprint allowlist
	if len(allowedFingerprints) > 0 {
		fingerprint := CertFingerprint(clientCert)
		if _, allowed := allowedFingerprints[fingerprint]; allowed {
			return nil
		}
	}

	// Check DN allowlist
	if len(allowedDNs) > 0 {
		dn := certCanonicalDN(clientCert)
		if _, allowed := allowedDNs[dn]; allowed {
			return nil
		}
	}

	// Build informative error message showing both human-readable and canonical DN
	// so operators can copy the canonical_dn value directly into config.
	fingerprint := CertFingerprint(clientCert)
	dn := CertDN(clientCert)
	canonDN := certCanonicalDN(clientCert)
	return status.Errorf(codes.PermissionDenied,
		"client certificate not in allowlist: fingerprint=%s, dn=%q, canonical_dn=%q", FormatFingerprint(fingerprint), dn, canonDN)
}

// fingerprintUnaryInterceptor returns a unary interceptor that verifies client cert fingerprints.
// allowedFingerprints maps normalized fingerprint -> friendly name.
// Deprecated: Use clientAuthUnaryInterceptor instead which supports both fingerprints and DNs.
func fingerprintUnaryInterceptor(allowedFingerprints map[string]string) grpc.UnaryServerInterceptor {
	return clientAuthUnaryInterceptor(allowedFingerprints, nil)
}

// fingerprintStreamInterceptor returns a stream interceptor that verifies client cert fingerprints.
// allowedFingerprints maps normalized fingerprint -> friendly name.
// Deprecated: Use clientAuthStreamInterceptor instead which supports both fingerprints and DNs.
func fingerprintStreamInterceptor(allowedFingerprints map[string]string) grpc.StreamServerInterceptor {
	return clientAuthStreamInterceptor(allowedFingerprints, nil)
}

// verifyClientFingerprint extracts the client certificate from the context and verifies its fingerprint.
// allowedFingerprints maps normalized fingerprint -> friendly name.
// Deprecated: Use verifyClientIdentity instead which supports both fingerprints and DNs.
func verifyClientFingerprint(ctx context.Context, allowedFingerprints map[string]string) error {
	return verifyClientIdentity(ctx, allowedFingerprints, nil)
}
