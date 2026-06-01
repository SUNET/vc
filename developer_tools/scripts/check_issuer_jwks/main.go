package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

var version = "n/a"

const (
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[1;33m"
	colorCyan   = "\033[0;36m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"

	iconOK   = "✅"
	iconFail = "❌"
	iconWarn = "⚠️ "
)

type issuerMetadata struct {
	CredentialIssuer string `json:"credential_issuer"`
	JWKsURI          string `json:"jwks_uri,omitempty"`
	SignedMetadata   string `json:"signed_metadata,omitempty"`
}

type jwtHeader struct {
	Alg string   `json:"alg"`
	Typ string   `json:"typ,omitempty"`
	Kid string   `json:"kid,omitempty"`
	X5C []string `json:"x5c,omitempty"`
}

type jwks struct {
	Keys []json.RawMessage `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	D   string `json:"d,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	DP  string `json:"dp,omitempty"`
	DQ  string `json:"dq,omitempty"`
	QI  string `json:"qi,omitempty"`
}

func main() {
	noColor := flag.Bool("no-color", false, "Disable colored output")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: check_issuer_jwks [flags] <host-url>\n\n")
		fmt.Fprintf(os.Stderr, "Check /jwks and x5c certificates from an OpenID Credential Issuer.\n\n")
		fmt.Fprintf(os.Stderr, "Example:\n  check_issuer_jwks https://issuer.example.com\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("check_issuer_jwks %s\n", version)
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	hostURL := strings.TrimRight(flag.Arg(0), "/")
	c := colors(!*noColor)
	var failures []string

	fmt.Printf("%s=== OpenID Credential Issuer JWKS & x5c Check ===%s\n", c.heading, c.reset)
	fmt.Printf("Host: %s%s%s\n\n", c.cyan, hostURL, c.reset)

	// Step 1: Fetch issuer metadata
	wellKnownURL := hostURL + "/.well-known/openid-credential-issuer"
	fmt.Printf("%s[1] Fetching %s%s\n", c.heading, wellKnownURL, c.reset)

	body, err := httpGet(wellKnownURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s ERROR: %v\n", c.fail, err)
		os.Exit(1)
	}

	var metadata issuerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		fmt.Fprintf(os.Stderr, "%s ERROR: invalid metadata JSON: %v\n", c.fail, err)
		os.Exit(1)
	}

	fmt.Printf("%s Retrieved openid-credential-issuer metadata\n", c.ok)
	if metadata.CredentialIssuer != "" {
		fmt.Printf("  credential_issuer: %s%s%s\n", c.cyan, metadata.CredentialIssuer, c.reset)
	}

	jwksURI := metadata.JWKsURI
	if jwksURI == "" {
		jwksURI = hostURL + "/jwks"
		fmt.Printf("  jwks_uri: %s%s%s (not in metadata, using default)\n\n", c.cyan, jwksURI, c.reset)
	} else {
		fmt.Printf("  jwks_uri: %s%s%s\n\n", c.cyan, jwksURI, c.reset)
	}

	// Step 2: Fetch JWKS
	fmt.Printf("%s[2] Fetching JWKS from %s%s\n", c.heading, jwksURI, c.reset)

	jwksBody, err := httpGet(jwksURI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s ERROR: %v\n", c.fail, err)
		os.Exit(1)
	}

	var keySet jwks
	if err := json.Unmarshal(jwksBody, &keySet); err != nil {
		fmt.Fprintf(os.Stderr, "%s ERROR: invalid JWKS JSON: %v\n", c.fail, err)
		os.Exit(1)
	}

	fmt.Printf("%s Found %s%d%s key(s)\n\n", c.ok, c.bold, len(keySet.Keys), c.reset)

	// Step 3: Check signed_metadata
	fmt.Printf("%s[3] Checking signed_metadata%s\n", c.heading, c.reset)
	if metadata.SignedMetadata == "" {
		fmt.Printf("  %ssigned_metadata: not present\n\n", c.warn)
		failures = append(failures, "signed_metadata not present")
	} else {
		fmt.Printf("  %s signed_metadata: present\n", c.ok)
		inspectSignedMetadata(metadata.SignedMetadata, keySet.Keys, c, &failures)
		fmt.Println()
	}

	// Step 4: Inspect each key
	fmt.Printf("%s[4] Key details%s\n", c.heading, c.reset)

	for i, rawKey := range keySet.Keys {
		var key jwkKey
		if err := json.Unmarshal(rawKey, &key); err != nil {
			fmt.Printf("  %s--- Key %d --- (parse error: %v)%s\n", c.bold, i+1, err, c.reset)
			continue
		}

		fmt.Printf("  %s--- Key %d ---%s\n", c.bold, i+1, c.reset)
		fmt.Printf("  kid: %s%s%s\n", c.cyan, valOrNA(key.Kid), c.reset)
		fmt.Printf("  kty: %s\n", valOrNA(key.Kty))
		fmt.Printf("  alg: %s\n", valOrNA(key.Alg))
		fmt.Printf("  use: %s\n", valOrNA(key.Use))
		if key.Crv != "" {
			fmt.Printf("  crv: %s\n", key.Crv)
		}

		var missing []string
		if key.Kid == "" {
			missing = append(missing, "kid")
		}
		if key.Kty == "" {
			missing = append(missing, "kty")
		}
		if key.Alg == "" {
			missing = append(missing, "alg")
		}

		switch key.Kty {
		case "EC":
			if key.Crv == "" {
				missing = append(missing, "crv")
			}
			if key.X == "" {
				missing = append(missing, "x")
			}
			if key.Y == "" {
				missing = append(missing, "y")
			}
		case "RSA":
			if key.N == "" {
				missing = append(missing, "n")
			}
			if key.E == "" {
				missing = append(missing, "e")
			}
		case "OKP":
			if key.Crv == "" {
				missing = append(missing, "crv")
			}
			if key.X == "" {
				missing = append(missing, "x")
			}
		case "":
			// already reported
		default:
			fmt.Printf("  %sunknown kty %q\n", c.warn, key.Kty)
		}

		if len(missing) > 0 {
			fmt.Printf("  %s INCOMPLETE: missing fields: %s\n", c.fail, strings.Join(missing, ", "))
			failures = append(failures, fmt.Sprintf("key %d incomplete: missing %s", i+1, strings.Join(missing, ", ")))
		} else {
			fmt.Printf("  %s key is complete\n", c.ok)
		}

		var privFields []string
		if key.D != "" {
			privFields = append(privFields, "d")
		}
		if key.P != "" {
			privFields = append(privFields, "p")
		}
		if key.Q != "" {
			privFields = append(privFields, "q")
		}
		if key.DP != "" {
			privFields = append(privFields, "dp")
		}
		if key.DQ != "" {
			privFields = append(privFields, "dq")
		}
		if key.QI != "" {
			privFields = append(privFields, "qi")
		}
		if len(privFields) > 0 {
			fmt.Printf("  %s PRIVATE KEY EXPOSED! Fields present: %s\n", c.fail, strings.Join(privFields, ", "))
			failures = append(failures, fmt.Sprintf("key %d: private key exposed", i+1))
		}
		fmt.Println()
	}

	// Bottom line
	fmt.Println()
	fmt.Printf("%s=== Result ===%s\n", c.heading, c.reset)
	if len(failures) == 0 {
		fmt.Printf("%s ALL CHECKS PASSED\n", c.ok)
	} else {
		fmt.Printf("%s VALIDATION FAILED (%d issue(s)):\n", c.fail, len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
}

func inspectSignedMetadata(jwtStr string, jwksKeys []json.RawMessage, c colorSet, failures *[]string) {
	parts := strings.SplitN(jwtStr, ".", 3)
	if len(parts) != 3 {
		fmt.Printf("  %s signed_metadata is not a valid JWT (expected 3 parts, got %d)\n", c.fail, len(parts))
		*failures = append(*failures, "signed_metadata: invalid JWT")
		return
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("  %s failed to decode JWT header: %v\n", c.fail, err)
		*failures = append(*failures, "signed_metadata: JWT header decode error")
		return
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		fmt.Printf("  %s failed to parse JWT header JSON: %v\n", c.fail, err)
		*failures = append(*failures, "signed_metadata: JWT header parse error")
		return
	}

	fmt.Printf("  JWT header:\n")
	fmt.Printf("    alg: %s\n", valOrNA(header.Alg))
	if header.Typ != "" {
		fmt.Printf("    typ: %s\n", header.Typ)
	}
	if header.Kid != "" {
		fmt.Printf("    kid: %s%s%s\n", c.cyan, header.Kid, c.reset)
	}

	if len(header.X5C) == 0 {
		fmt.Printf("    %s x5c: not present (required)\n", c.fail)
		*failures = append(*failures, "signed_metadata: x5c not present")
		return
	}

	fmt.Printf("    %s x5c: present (%d cert(s) in chain)\n", c.ok, len(header.X5C))

	certs := make([]*x509.Certificate, 0, len(header.X5C))
	for j, certB64 := range header.X5C {
		der, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			fmt.Printf("      %s [cert %d] base64 decode error: %v\n", c.fail, j+1, err)
			continue
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			fmt.Printf("      %s [cert %d] x509 parse error: %v\n", c.fail, j+1, err)
			continue
		}
		certs = append(certs, cert)

		label := "Intermediate"
		if j == 0 {
			label = "Leaf"
		} else if j == len(header.X5C)-1 && j > 0 {
			label = "Root/CA"
		}

		fmt.Printf("      %s[%s] cert %d:%s\n", c.bold, label, j+1, c.reset)
		fmt.Printf("        Subject: %s\n", cert.Subject)
		fmt.Printf("        Issuer:  %s\n", cert.Issuer)
		fmt.Printf("        Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
		fmt.Printf("        Not After:  %s\n", cert.NotAfter.Format(time.RFC3339))
		fmt.Printf("        Serial:     %s\n", cert.SerialNumber)

		now := time.Now()
		if now.Before(cert.NotBefore) {
			fmt.Printf("        %s Status: not yet valid\n", c.fail)
			*failures = append(*failures, fmt.Sprintf("signed_metadata: cert %d not yet valid", j+1))
		} else if now.After(cert.NotAfter) {
			fmt.Printf("        %s Status: EXPIRED\n", c.fail)
			*failures = append(*failures, fmt.Sprintf("signed_metadata: cert %d expired", j+1))
		} else {
			fmt.Printf("        %s Status: valid\n", c.ok)
			if time.Until(cert.NotAfter) < 30*24*time.Hour {
				fmt.Printf("        %sExpires within 30 days\n", c.warn)
			}
		}
	}

	if len(certs) > 1 {
		fmt.Printf("    %sChain linkage:%s\n", c.heading, c.reset)
		chainOK := true
		for j := 0; j < len(certs)-1; j++ {
			child := certs[j]
			parent := certs[j+1]
			if child.Issuer.String() != parent.Subject.String() {
				fmt.Printf("      %s cert %d issuer (%s) != cert %d subject (%s)\n",
					c.fail, j+1, child.Issuer, j+2, parent.Subject)
				chainOK = false
			} else {
				fmt.Printf("      %s cert %d -> cert %d: issuer/subject match\n", c.ok, j+1, j+2)
			}
			if err := child.CheckSignatureFrom(parent); err != nil {
				fmt.Printf("      %s cert %d signature not verified by cert %d: %v\n",
					c.fail, j+1, j+2, err)
				chainOK = false
			} else {
				fmt.Printf("      %s cert %d -> cert %d: signature valid\n", c.ok, j+1, j+2)
			}
		}
		fmt.Printf("    %sChain verification:%s\n", c.heading, c.reset)
		if !chainOK {
			fmt.Printf("      %s Chain is NOT a valid chain\n", c.fail)
			*failures = append(*failures, "signed_metadata: x5c chain linkage broken")
		} else if err := verifyChain(certs); err != nil {
			fmt.Printf("      %s Chain verification failed: %v\n", c.fail, err)
			*failures = append(*failures, fmt.Sprintf("signed_metadata: chain verification failed: %v", err))
		} else {
			fmt.Printf("      %s Chain is valid\n", c.ok)
		}
	}

	// Verify JWT signature using x5c leaf certificate
	fmt.Printf("    %sSignature verification (x5c leaf cert -> JWT):%s\n", c.heading, c.reset)
	if len(certs) > 0 {
		verifyJWTWithCert(jwtStr, header, certs[0], c, failures)
	}

	// Check that JWKS key matches x5c leaf public key
	fmt.Printf("    %sJWKS key matches x5c leaf cert:%s\n", c.heading, c.reset)
	if len(certs) > 0 {
		checkJWKSMatchesX5C(header, certs[0], jwksKeys, c, failures)
	}
}

func verifyJWTWithCert(jwtStr string, header jwtHeader, leafCert *x509.Certificate, c colorSet, failures *[]string) {
	parts := strings.SplitN(jwtStr, ".", 3)
	if len(parts) != 3 {
		fmt.Printf("      %s invalid JWT\n", c.fail)
		*failures = append(*failures, "signed_metadata: invalid JWT for signature check")
		return
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		fmt.Printf("      %s failed to decode signature: %v\n", c.fail, err)
		*failures = append(*failures, "signed_metadata: signature decode error")
		return
	}

	hashFunc, err := algToHash(header.Alg)
	if err != nil {
		fmt.Printf("      %s %v\n", c.fail, err)
		*failures = append(*failures, fmt.Sprintf("signed_metadata: %v", err))
		return
	}

	h := hashFunc.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	switch key := leafCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, sigBytes) {
			fmt.Printf("      %s ECDSA signature verification FAILED\n", c.fail)
			*failures = append(*failures, "signed_metadata: signature verification failed")
		} else {
			fmt.Printf("      %s Signature is valid (signed by x5c leaf cert)\n", c.ok)
		}
	case *rsa.PublicKey:
		var rsaErr error
		if strings.HasPrefix(header.Alg, "PS") {
			rsaErr = rsa.VerifyPSS(key, hashFunc, digest, sigBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			rsaErr = rsa.VerifyPKCS1v15(key, hashFunc, digest, sigBytes)
		}
		if rsaErr != nil {
			fmt.Printf("      %s RSA signature verification FAILED\n", c.fail)
			*failures = append(*failures, "signed_metadata: signature verification failed")
		} else {
			scheme := "PKCS1v15"
			if strings.HasPrefix(header.Alg, "PS") {
				scheme = "PSS"
			}
			fmt.Printf("      %s Signature is valid (signed by x5c leaf cert, RSA-%s)\n", c.ok, scheme)
		}
	default:
		fmt.Printf("      %s unsupported key type in cert: %T\n", c.fail, leafCert.PublicKey)
		*failures = append(*failures, "signed_metadata: unsupported key type")
	}
}

func checkJWKSMatchesX5C(header jwtHeader, leafCert *x509.Certificate, jwksKeys []json.RawMessage, c colorSet, failures *[]string) {
	var matchedRaw json.RawMessage
	for _, rawKey := range jwksKeys {
		var k jwkKey
		if err := json.Unmarshal(rawKey, &k); err != nil {
			continue
		}
		if header.Kid != "" && k.Kid == header.Kid {
			matchedRaw = rawKey
			break
		}
	}

	if matchedRaw == nil {
		if len(jwksKeys) == 1 {
			fmt.Printf("      %sno kid match, trying the only key in JWKS\n", c.warn)
			matchedRaw = jwksKeys[0]
		} else {
			fmt.Printf("      %s no key in JWKS matches kid %q\n", c.fail, header.Kid)
			*failures = append(*failures, fmt.Sprintf("signed_metadata: no JWKS key matches kid %q", header.Kid))
			return
		}
	}

	var matched jwkKey
	if err := json.Unmarshal(matchedRaw, &matched); err != nil {
		fmt.Printf("      %s failed to parse matched key: %v\n", c.fail, err)
		return
	}

	fmt.Printf("      Matched JWKS key kid=%s%s%s\n", c.cyan, matched.Kid, c.reset)

	jwkPub, err := jwkToPublicKey(matched)
	if err != nil {
		fmt.Printf("      %s failed to parse public key from JWK: %v\n", c.fail, err)
		return
	}

	certPub := leafCert.PublicKey
	match := false
	switch jk := jwkPub.(type) {
	case *ecdsa.PublicKey:
		if ck, ok := certPub.(*ecdsa.PublicKey); ok {
			match = jk.Curve == ck.Curve && jk.X.Cmp(ck.X) == 0 && jk.Y.Cmp(ck.Y) == 0
		}
	case *rsa.PublicKey:
		if ck, ok := certPub.(*rsa.PublicKey); ok {
			match = jk.N.Cmp(ck.N) == 0 && jk.E == ck.E
		}
	}

	if match {
		fmt.Printf("      %s JWKS key matches x5c leaf certificate public key\n", c.ok)
	} else {
		fmt.Printf("      %s JWKS key does NOT match x5c leaf certificate public key\n", c.fail)
		*failures = append(*failures, "signed_metadata: JWKS key does not match x5c leaf cert")
	}
}

func jwkToPublicKey(key jwkKey) (crypto.PublicKey, error) {
	switch key.Kty {
	case "EC":
		xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil, fmt.Errorf("decode x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return nil, fmt.Errorf("decode y: %w", err)
		}
		var curve elliptic.Curve
		switch key.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", key.Crv)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, fmt.Errorf("decode n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, fmt.Errorf("decode e: %w", err)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
	}
}

func algToHash(alg string) (crypto.Hash, error) {
	switch alg {
	case "ES256", "RS256", "PS256":
		return crypto.SHA256, nil
	case "ES384", "RS384", "PS384":
		return crypto.SHA384, nil
	case "ES512", "RS512", "PS512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func httpGet(url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func verifyChain(certs []*x509.Certificate) error {
	if len(certs) < 2 {
		return fmt.Errorf("need at least 2 certificates")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])
	for _, c := range certs[1 : len(certs)-1] {
		intermediates.AddCert(c)
	}

	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func valOrNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

type colorSet struct {
	ok, fail, warn, cyan, bold, heading, reset string
}

func colors(enabled bool) colorSet {
	if !enabled {
		return colorSet{ok: iconOK, fail: iconFail, warn: iconWarn}
	}
	return colorSet{
		ok:      colorGreen + iconOK + colorReset,
		fail:    colorRed + iconFail + colorReset,
		warn:    colorYellow + iconWarn + colorReset,
		cyan:    colorCyan,
		bold:    colorBold,
		heading: colorYellow + colorBold,
		reset:   colorReset,
	}
}
