package httpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/gin-gonic/gin"
)

// maxEncryptedRequestBytes bounds an encrypted Credential or Deferred
// Credential Request before anything is decrypted. The plaintext a wallet
// sends is a few kilobytes of JSON; this leaves room for a batch of key
// proofs and nothing like enough for a request worth buffering.
const maxEncryptedRequestBytes = 256 * 1024

// acceptEncryptedRequest reads an encrypted Credential or Deferred Credential
// Request and rewrites c.Request so the ordinary binder sees the JSON it
// carried. It reports whether the request arrived encrypted.
//
// OpenID4VCI 1.0 §8.3 gives an encrypted request the media type
// application/jwt, which is what distinguishes one from a plain JSON request.
func (s *Service) acceptEncryptedRequest(c *gin.Context) (bool, error) {
	if c.ContentType() != openid4vci.MediaTypeJWT {
		if s.credentialEncryption.RequestEncryptionRequired() {
			return false, &openid4vci.Error{
				Err:              openid4vci.ErrInvalidEncryptionParameters,
				ErrorDescription: "this Credential Issuer requires encrypted requests: send an application/jwt JWE built from the credential_request_encryption metadata",
			}
		}
		return false, nil
	}

	if c.Request.Body == nil {
		return false, &openid4vci.Error{
			Err:              openid4vci.ErrInvalidEncryptionParameters,
			ErrorDescription: "the request has no body",
		}
	}

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxEncryptedRequestBytes+1))
	if err != nil {
		return false, &openid4vci.Error{
			Err:              openid4vci.ErrInvalidEncryptionParameters,
			ErrorDescription: "the request body could not be read",
		}
	}
	if len(body) > maxEncryptedRequestBytes {
		return false, &openid4vci.Error{
			Err:              openid4vci.ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("the encrypted request exceeds %d bytes", maxEncryptedRequestBytes),
		}
	}

	plaintext, err := s.credentialEncryption.DecryptRequest(bytes.TrimSpace(body))
	if err != nil {
		return false, err
	}

	c.Request.Body = io.NopCloser(bytes.NewReader(plaintext))
	c.Request.ContentLength = int64(len(plaintext))
	c.Request.Header.Set("Content-Type", gin.MIMEJSON)

	return true, nil
}

// checkResponseEncryption applies the two rules §8.3 and §12.2.4 put on the
// wallet's credential_response_encryption, before any credential is made.
//
//   - A wallet that asks for an encrypted response must have sent an
//     encrypted request. §8.3: "Credential Request encryption MUST be used if
//     the credential_response_encryption parameter is included, to prevent it
//     being substituted by an attacker" - otherwise anyone able to rewrite
//     the request can swap in a key of their own and read the credential.
//   - A wallet must supply the parameters at all when this issuer publishes
//     encryption_required.
//
// The parameters are validated here too, so a request this issuer cannot
// answer is refused before it has issued a credential it would discard.
func (s *Service) checkResponseEncryption(params *openid4vci.CredentialResponseEncryption, requestWasEncrypted bool) error {
	if params == nil {
		if s.credentialEncryption.ResponseEncryptionRequired() {
			return &openid4vci.Error{
				Err:              openid4vci.ErrInvalidEncryptionParameters,
				ErrorDescription: "this Credential Issuer requires an encrypted response: send credential_response_encryption in the request",
			}
		}
		return nil
	}

	if !s.credentialEncryption.Enabled() {
		return &openid4vci.Error{
			Err:              openid4vci.ErrInvalidEncryptionParameters,
			ErrorDescription: "this Credential Issuer does not support credential_response_encryption",
		}
	}

	if !requestWasEncrypted {
		return &openid4vci.Error{
			Err:              openid4vci.ErrInvalidEncryptionParameters,
			ErrorDescription: "credential_response_encryption requires an encrypted request, so the encryption key cannot be substituted in transit",
		}
	}

	return params.Validate()
}

// writeEncryptedReply encrypts a reply with the wallet's parameters and
// writes it as application/jwt. It returns (nil, nil) on success, which is
// how a handler tells RegEndpoint that it wrote the response itself.
func (s *Service) writeEncryptedReply(c *gin.Context, params *openid4vci.CredentialResponseEncryption, reply any) (any, error) {
	payload, err := json.Marshal(reply)
	if err != nil {
		return nil, fmt.Errorf("encoding the credential response for encryption: %w", err)
	}

	encrypted, err := s.credentialEncryption.EncryptResponse(params, payload)
	if err != nil {
		return nil, err
	}

	c.Data(http.StatusOK, openid4vci.MediaTypeJWT, []byte(encrypted))

	return nil, nil
}
