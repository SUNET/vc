package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/SUNET/vc/pkg/pki"
	"github.com/gin-gonic/gin"
)

// endpointDIDDocument serves the DID Document at /.well-known/did.json
// per the did:web method specification (https://w3c-ccg.github.io/did-method-web/).
func (s *Service) endpointDIDDocument(ctx context.Context, c *gin.Context) (any, error) {
	if s.cfg.Verifier.ClientIDScheme != "did" || s.cfg.Verifier.DID == "" {
		c.Status(http.StatusNotFound)
		return nil, nil
	}

	signerConfig := pki.NewSignerConfig(s.cfg.Verifier.KeyConfig)
	jwk, err := signerConfig.GetJWK()
	if err != nil {
		return nil, err
	}

	// Build the DID Document
	verificationMethodID := s.cfg.Verifier.DID + "#key-1"

	// Use the JWK's JSON serialization for the actual key data
	pubJWK := jwk.Public()
	pubJWKBytes, err := pubJWK.MarshalJSON()
	if err != nil {
		return nil, err
	}
	// Parse back to get proper structure
	var pubJWKParsed map[string]any
	if err := json.Unmarshal(pubJWKBytes, &pubJWKParsed); err != nil {
		return nil, err
	}
	// Remove non-JWK fields that jose adds (certificates are separate from DID)
	delete(pubJWKParsed, "x5c")
	delete(pubJWKParsed, "x5t")
	delete(pubJWKParsed, "x5t#S256")
	delete(pubJWKParsed, "x5u")

	serviceEndpoint := s.cfg.Verifier.PublicURL

	didDoc := map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		"id": s.cfg.Verifier.DID,
		"verificationMethod": []map[string]any{
			{
				"id":           verificationMethodID,
				"type":         "JsonWebKey2020",
				"controller":   s.cfg.Verifier.DID,
				"publicKeyJwk": pubJWKParsed,
			},
		},
		"authentication":  []string{verificationMethodID},
		"assertionMethod": []string{verificationMethodID},
		"service": []map[string]any{
			{
				"id":              s.cfg.Verifier.DID + "#verifier",
				"type":            "OpenID4VP",
				"serviceEndpoint": serviceEndpoint,
			},
		},
	}

	// Derive linked domains if PublicURL is set
	if s.cfg.Verifier.PublicURL != "" {
		u, parseErr := url.Parse(s.cfg.Verifier.PublicURL)
		if parseErr == nil && u.Scheme != "" && u.Host != "" {
			didDoc["alsoKnownAs"] = []string{u.Scheme + "://" + u.Host}
		}
	}

	c.JSON(http.StatusOK, didDoc)
	return nil, nil
}
