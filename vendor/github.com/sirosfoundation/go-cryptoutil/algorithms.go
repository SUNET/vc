package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
)

// Algorithm describes a cryptographic algorithm across multiple protocol domains.
type Algorithm struct {
	Name    string      // Canonical name: "P-256", "RS256", etc.
	JWS     string      // JWS/JWA identifier (RFC 7518)
	XMLDSIG string      // XML-DSIG algorithm URI
	COSE    int         // COSE algorithm number (RFC 9053), 0 if not assigned
	Hash    crypto.Hash // Hash function for this algorithm
	KeyType string      // "EC", "RSA", "OKP", etc.
}

// AlgorithmRegistry maps public keys to algorithms across protocol domains.
type AlgorithmRegistry struct {
	// CurveAlgorithms maps elliptic curve Params().Name to Algorithm.
	CurveAlgorithms map[string]*Algorithm
	// xmldsigIndex maps XML-DSIG algorithm URI to Algorithm.
	xmldsigIndex map[string]*Algorithm
	// All is the full list of registered algorithms.
	All []*Algorithm
}

// NewAlgorithmRegistry returns a registry pre-populated with standard NIST algorithms.
func NewAlgorithmRegistry() *AlgorithmRegistry {
	reg := &AlgorithmRegistry{
		CurveAlgorithms: make(map[string]*Algorithm),
		xmldsigIndex:    make(map[string]*Algorithm),
	}
	for _, a := range standardAlgorithms {
		reg.Register(a)
	}
	return reg
}

// Register adds an algorithm to the registry. If the algorithm has KeyType "EC",
// it is also indexed by its Name in CurveAlgorithms.
func (r *AlgorithmRegistry) Register(a *Algorithm) {
	r.All = append(r.All, a)
	if a.KeyType == "EC" {
		r.CurveAlgorithms[a.Name] = a
	}
	if a.XMLDSIG != "" {
		r.xmldsigIndex[a.XMLDSIG] = a
	}
}

// ByXMLDSIG returns the Algorithm registered for the given XML-DSIG URI,
// or nil if the URI is not recognized.
func (r *AlgorithmRegistry) ByXMLDSIG(uri string) *Algorithm {
	return r.xmldsigIndex[uri]
}

// ForKey returns the Algorithm for the given public key, or an error if the
// key type or curve is not recognized.
func (r *AlgorithmRegistry) ForKey(pub crypto.PublicKey) (*Algorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		name := k.Curve.Params().Name
		if a, ok := r.CurveAlgorithms[name]; ok {
			return a, nil
		}
		return nil, fmt.Errorf("cryptoutil: unsupported elliptic curve %q", name)
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		switch {
		case bits >= 4096:
			return algRS512, nil
		case bits >= 3072:
			return algRS384, nil
		default:
			return algRS256, nil
		}
	case ed25519.PublicKey:
		return algEdDSA, nil
	default:
		return nil, fmt.Errorf("cryptoutil: unsupported key type %T", pub)
	}
}

// JWSAlgorithm returns the JWS/JWA algorithm name for the given public key.
func (r *AlgorithmRegistry) JWSAlgorithm(pub crypto.PublicKey) (string, error) {
	a, err := r.ForKey(pub)
	if err != nil {
		return "", err
	}
	return a.JWS, nil
}

// XMLDSIGAlgorithm returns the XML-DSIG algorithm URI for the given public key.
func (r *AlgorithmRegistry) XMLDSIGAlgorithm(pub crypto.PublicKey) (string, error) {
	a, err := r.ForKey(pub)
	if err != nil {
		return "", err
	}
	return a.XMLDSIG, nil
}

// COSEAlgorithm returns the COSE algorithm number for the given public key.
func (r *AlgorithmRegistry) COSEAlgorithm(pub crypto.PublicKey) (int, error) {
	a, err := r.ForKey(pub)
	if err != nil {
		return 0, err
	}
	if a.COSE == 0 {
		return 0, fmt.Errorf("cryptoutil: no COSE algorithm defined for %s", a.Name)
	}
	return a.COSE, nil
}

// CurveName returns the JWK curve name (e.g. "P-256") for an elliptic curve key.
func (r *AlgorithmRegistry) CurveName(pub *ecdsa.PublicKey) (string, error) {
	name := pub.Curve.Params().Name
	if _, ok := r.CurveAlgorithms[name]; ok {
		return name, nil
	}
	return "", fmt.Errorf("cryptoutil: unsupported curve %q", name)
}

// Standard algorithms.
var (
	algES256 = &Algorithm{Name: "P-256", JWS: "ES256", XMLDSIG: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", COSE: -7, Hash: crypto.SHA256, KeyType: "EC"}
	algES384 = &Algorithm{Name: "P-384", JWS: "ES384", XMLDSIG: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", COSE: -35, Hash: crypto.SHA384, KeyType: "EC"}
	algES512 = &Algorithm{Name: "P-521", JWS: "ES512", XMLDSIG: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", COSE: -36, Hash: crypto.SHA512, KeyType: "EC"}
	algRS256 = &Algorithm{Name: "RS256", JWS: "RS256", XMLDSIG: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", COSE: -257, Hash: crypto.SHA256, KeyType: "RSA"}
	algRS384 = &Algorithm{Name: "RS384", JWS: "RS384", XMLDSIG: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", COSE: -258, Hash: crypto.SHA384, KeyType: "RSA"}
	algRS512 = &Algorithm{Name: "RS512", JWS: "RS512", XMLDSIG: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", COSE: -259, Hash: crypto.SHA512, KeyType: "RSA"}
	algEdDSA = &Algorithm{Name: "Ed25519", JWS: "EdDSA", XMLDSIG: "", COSE: -8, Hash: 0, KeyType: "OKP"}
)

var standardAlgorithms = []*Algorithm{algES256, algES384, algES512, algRS256, algRS384, algRS512, algEdDSA}

// ECDSAComponentSize returns the expected byte size of each r/s component
// for the given curve. This is useful when converting between ASN.1 DER and
// raw r||s ECDSA signatures.
func ECDSAComponentSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}
