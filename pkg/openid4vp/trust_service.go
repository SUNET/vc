package openid4vp

import (
	"encoding/base64"
	"fmt"

	"github.com/SUNET/vc/pkg/pki"

	"github.com/sirosfoundation/go-cryptoutil"
)

type TrustService struct{}

//func (ts *TrustService) ExtractPublicKeyFromCnfMap(cnf map[string]any) (any, error) {
//	jwkMap, ok := cnf["jwk"]
//	if !ok {
//		return nil, fmt.Errorf("missing 'jwk' field in cnf")
//	}
//
//	jwkJSON, err := json.Marshal(jwkMap)
//	if err != nil {
//		return nil, fmt.Errorf("failed to marshal jwk to JSON: %w", err)
//	}
//
//	var jwk jose.JSONWebKey
//	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
//		return nil, fmt.Errorf("failed to unmarshal JWK: %w", err)
//	}
//
//	if !jwk.Valid() {
//		return nil, fmt.Errorf("invalid JWK")
//	}
//
//	return jwk.Key, nil
//}

func (ts *TrustService) ExtractPublicKeyFromX5C(x5cBase64 string, ext ...*cryptoutil.Extensions) (any, error) {
	derCert, err := base64.StdEncoding.DecodeString(x5cBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 x5c certificate: %w", err)
	}

	// Use the first extension if provided, otherwise nil for stdlib fallback
	var cryptoExt *cryptoutil.Extensions
	if len(ext) > 0 {
		cryptoExt = ext[0]
	}

	cert, err := pki.ParseCertificate(derCert, cryptoExt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.PublicKey, nil
}

//func (ts *TrustService) FetchPublicKeyFromJWKS(jwksURL string, kid string) (crypto.PublicKey, error) {
//	set, err := jwk.Fetch(context.Background(), jwksURL)
//	if err != nil {
//		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
//	}
//
//	key, found := set.LookupKeyID(kid)
//	if !found {
//		return nil, fmt.Errorf("no key found for kid: %s", kid)
//	}
//
//	var pubkey crypto.PublicKey
//	if err := key.Raw(&pubkey); err != nil {
//		return nil, fmt.Errorf("failed to get raw public key: %w", err)
//	}
//
//	return pubkey, nil
//}
