package openid4vci

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Encryption of Credential and Deferred Credential messages, per OpenID4VCI
// 1.0 §8.3 (Encrypted Credential Requests and Responses) and the
// credential_request_encryption / credential_response_encryption metadata
// parameters in §12.2.4.
//
// The algorithm lists below are the single source of truth: both the
// published metadata and the checks that refuse a request read them. Two
// lists that must agree and are written down twice eventually disagree, and
// an issuer that advertises what it will not accept is worse than one that
// advertises nothing.
const (
	// MediaTypeJWT is the media type §8.3 gives an encrypted Credential
	// Request or Response. It is how the endpoint tells an encrypted request
	// from a plain JSON one.
	MediaTypeJWT = "application/jwt"

	// AlgECDHESA256KW is the only JWE key management algorithm vc performs.
	// ECDH-ES with an AES-256 key wrap over P-256: it is what EUDI wallets
	// send, it is what the verifier already uses for JARM, and the key is
	// small enough to live in an HSM slot.
	AlgECDHESA256KW = "ECDH-ES+A256KW"

	// EncA256GCM is the only JWE content encryption algorithm vc performs.
	EncA256GCM = "A256GCM"

	// ZipDeflate is the only JWE compression algorithm vc performs, and only
	// when compressing a response. See RequestEncryptionZipValuesSupported.
	ZipDeflate = "DEF"
)

var (
	// RequestEncryptionEncValuesSupported is what a wallet may use to encrypt
	// a Credential Request to this issuer.
	RequestEncryptionEncValuesSupported = []string{EncA256GCM}

	// RequestEncryptionZipValuesSupported is empty on purpose, and §12.2.4
	// reads an absent zip_values_supported as "no compression algorithms are
	// supported". Decompressing attacker-supplied input before it has been
	// authorized is a bounded amount of work for the sender and an unbounded
	// amount for us; compressing our own response is not. So compression is
	// offered in one direction only.
	RequestEncryptionZipValuesSupported []string

	// ResponseEncryptionAlgValuesSupported is the set of JWE key management
	// algorithms vc can use for the wallet's key. §8.3 requires that key to
	// carry an alg and that the JWE use it, so this is also the set of alg
	// values a wallet's jwk may name.
	ResponseEncryptionAlgValuesSupported = []string{AlgECDHESA256KW}

	// ResponseEncryptionEncValuesSupported is the set of content encryption
	// algorithms a wallet may ask for in credential_response_encryption.enc.
	ResponseEncryptionEncValuesSupported = []string{EncA256GCM}

	// ResponseEncryptionZipValuesSupported is the set of compression
	// algorithms a wallet may ask for in credential_response_encryption.zip.
	ResponseEncryptionZipValuesSupported = []string{ZipDeflate}
)

// CredentialEncryption decrypts Credential and Deferred Credential Requests
// and encrypts the corresponding Responses.
//
// A zero value is unusable; NewCredentialEncryption builds one, and a nil
// *CredentialEncryption is a deployment with no encryption key configured.
// Every method is nil-safe so the call sites do not each repeat that check.
type CredentialEncryption struct {
	// private is the key set used to decrypt requests. Each key carries a kid
	// (its RFC 7638 thumbprint) and an alg, so a wallet can name the key it
	// encrypted to and rotation is adding a key rather than a flag day.
	private jwk.Set

	// publicJWKS is the serialized public half, published in metadata.
	// Rendered once: it is the same bytes on every metadata request.
	publicJWKS json.RawMessage

	requestRequired  bool
	responseRequired bool
}

// NewCredentialEncryption builds the encrypter from the issuer's private
// key-agreement keys. Keys are ECDSA P-256 private keys; anything else is
// refused here rather than at the first request, because a key that cannot
// perform ECDH-ES is a configuration error and the metadata would otherwise
// advertise a capability the endpoint does not have.
func NewCredentialEncryption(keys []crypto.PrivateKey, requestRequired, responseRequired bool) (*CredentialEncryption, error) {
	if len(keys) == 0 {
		if requestRequired || responseRequired {
			return nil, fmt.Errorf("credential encryption is required but no encryption key is configured")
		}
		return nil, nil
	}

	private := jwk.NewSet()
	public := jwk.NewSet()
	seen := map[string]bool{}

	for i, raw := range keys {
		ec, ok := raw.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("credential encryption key %d: want an ECDSA P-256 private key, got %T", i, raw)
		}
		if ec.Curve != elliptic.P256() {
			return nil, fmt.Errorf("credential encryption key %d: want curve P-256, got %s", i, ec.Curve.Params().Name)
		}

		key, err := jwk.Import(ec)
		if err != nil {
			return nil, fmt.Errorf("credential encryption key %d: %w", i, err)
		}

		// kid is the RFC 7638 thumbprint, so it is stable across re-encodings
		// of the same key and says nothing an operator has to keep in sync.
		sum, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("credential encryption key %d: thumbprint: %w", i, err)
		}
		kid := base64.RawURLEncoding.EncodeToString(sum)
		if seen[kid] {
			return nil, fmt.Errorf("credential encryption key %d is a duplicate of an earlier key (kid %s)", i, kid)
		}
		seen[kid] = true

		if err := setKeyMetadata(key, kid); err != nil {
			return nil, fmt.Errorf("credential encryption key %d: %w", i, err)
		}
		if err := private.AddKey(key); err != nil {
			return nil, fmt.Errorf("credential encryption key %d: %w", i, err)
		}

		pub, err := key.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("credential encryption key %d: public half: %w", i, err)
		}
		if err := setKeyMetadata(pub, kid); err != nil {
			return nil, fmt.Errorf("credential encryption key %d: %w", i, err)
		}
		if err := public.AddKey(pub); err != nil {
			return nil, fmt.Errorf("credential encryption key %d: %w", i, err)
		}
	}

	encoded, err := json.Marshal(public)
	if err != nil {
		return nil, fmt.Errorf("credential encryption: encode public key set: %w", err)
	}

	return &CredentialEncryption{
		private:          private,
		publicJWKS:       encoded,
		requestRequired:  requestRequired,
		responseRequired: responseRequired,
	}, nil
}

// setKeyMetadata stamps the kid, alg and use a wallet needs in order to pick
// this key and know what to do with it. §8.3: "The alg parameter MUST be
// present. The JWE alg algorithm used MUST be equal to the alg value of the
// chosen JWK."
func setKeyMetadata(key jwk.Key, kid string) error {
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return err
	}
	if err := key.Set(jwk.AlgorithmKey, AlgECDHESA256KW); err != nil {
		return err
	}
	return key.Set(jwk.KeyUsageKey, "enc")
}

// Enabled reports whether this deployment has an encryption key at all.
func (e *CredentialEncryption) Enabled() bool { return e != nil && e.private != nil }

// RequestEncryptionRequired reports whether a Credential Request must arrive
// encrypted.
func (e *CredentialEncryption) RequestEncryptionRequired() bool {
	return e.Enabled() && e.requestRequired
}

// ResponseEncryptionRequired reports whether a wallet must supply response
// encryption parameters.
func (e *CredentialEncryption) ResponseEncryptionRequired() bool {
	return e.Enabled() && e.responseRequired
}

// RequestMetadata returns the credential_request_encryption object for the
// issuer metadata, or nil when no key is configured - §12.2.4 makes the whole
// object OPTIONAL, and omitting it is how an issuer says it cannot do this.
func (e *CredentialEncryption) RequestMetadata() *MetadataCredentialRequestEncryption {
	if !e.Enabled() {
		return nil
	}
	return &MetadataCredentialRequestEncryption{
		JWKS:               e.publicJWKS,
		EncValuesSupported: RequestEncryptionEncValuesSupported,
		ZipValuesSupported: RequestEncryptionZipValuesSupported,
		EncryptionRequired: e.requestRequired,
	}
}

// ResponseMetadata returns the credential_response_encryption object for the
// issuer metadata, or nil when no key is configured.
//
// Response encryption uses the wallet's key, not ours, so in principle it
// needs no issuer key at all. It is still gated on one: §8.3 says "Credential
// Request encryption MUST be used if the credential_response_encryption
// parameter is included, to prevent it being substituted by an attacker", so
// advertising response encryption without the means to accept an encrypted
// request would advertise something no conformant wallet could use.
func (e *CredentialEncryption) ResponseMetadata() *MetadataCredentialResponseEncryption {
	if !e.Enabled() {
		return nil
	}
	return &MetadataCredentialResponseEncryption{
		AlgValuesSupported: ResponseEncryptionAlgValuesSupported,
		EncValuesSupported: ResponseEncryptionEncValuesSupported,
		ZipValuesSupported: ResponseEncryptionZipValuesSupported,
		EncryptionRequired: e.responseRequired,
	}
}

// DecryptRequest decrypts an encrypted Credential or Deferred Credential
// Request body and returns the JSON it carried.
func (e *CredentialEncryption) DecryptRequest(body []byte) ([]byte, error) {
	if !e.Enabled() {
		return nil, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "this Credential Issuer does not accept encrypted requests",
		}
	}

	msg, err := jwe.Parse(body)
	if err != nil {
		return nil, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "the request is not a well-formed JWE",
		}
	}

	headers := msg.ProtectedHeaders()

	if alg, ok := headers.Algorithm(); !ok || alg.String() != AlgECDHESA256KW {
		return nil, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("unsupported request encryption alg; this Credential Issuer accepts %s", AlgECDHESA256KW),
		}
	}
	if enc, ok := headers.ContentEncryption(); !ok || !contains(RequestEncryptionEncValuesSupported, enc.String()) {
		return nil, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("unsupported request encryption enc; this Credential Issuer accepts %v", RequestEncryptionEncValuesSupported),
		}
	}
	// zip_values_supported is absent from this issuer's metadata, which
	// §12.2.4 defines as supporting none. Refusing here rather than letting
	// the JWE library inflate first is the point of not advertising it.
	if zip, ok := headers.Compression(); ok && zip.String() != "" {
		return nil, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "this Credential Issuer does not support compressed requests",
		}
	}

	// WithRequireKid: the wallet must name the key it encrypted to. Every key
	// this issuer publishes carries a kid, so a request without one was not
	// built from this issuer's metadata.
	plaintext, err := jwe.Decrypt(body, jwe.WithKeySet(e.private, jwe.WithRequireKid(true)))
	if err != nil {
		return nil, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "the request could not be decrypted with any of this Credential Issuer's keys",
		}
	}

	return plaintext, nil
}

// EncryptResponse encrypts a response body with the parameters the wallet
// supplied in the request.
func (e *CredentialEncryption) EncryptResponse(params *CredentialResponseEncryption, payload []byte) (string, error) {
	if params == nil {
		return "", &Error{Err: ErrInvalidEncryptionParameters, ErrorDescription: "no response encryption parameters"}
	}

	key, alg, err := params.recipientKey()
	if err != nil {
		return "", err
	}

	if !contains(ResponseEncryptionEncValuesSupported, params.Enc) {
		return "", &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("unsupported credential_response_encryption.enc %q; this Credential Issuer supports %v", params.Enc, ResponseEncryptionEncValuesSupported),
		}
	}
	if params.Zip != "" && !contains(ResponseEncryptionZipValuesSupported, params.Zip) {
		return "", &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("unsupported credential_response_encryption.zip %q; this Credential Issuer supports %v", params.Zip, ResponseEncryptionZipValuesSupported),
		}
	}

	headers := jwe.NewHeaders()
	if kid, ok := key.KeyID(); ok && kid != "" {
		// §8.3: if the selected public key carries a kid, the JWE must repeat
		// it, so the wallet can tell which of its keys to decrypt with.
		if err := headers.Set(jwe.KeyIDKey, kid); err != nil {
			return "", err
		}
	}

	options := []jwe.EncryptOption{
		jwe.WithKey(alg, key),
		jwe.WithContentEncryption(jwa.NewContentEncryptionAlgorithm(params.Enc)),
		jwe.WithProtectedHeaders(headers),
	}
	if params.Zip != "" {
		options = append(options, jwe.WithCompress(jwa.NewCompressionAlgorithm(params.Zip)))
	}

	encrypted, err := jwe.Encrypt(payload, options...)
	if err != nil {
		return "", fmt.Errorf("encrypting the credential response: %w", err)
	}

	return string(encrypted), nil
}

// Validate checks the wallet's response encryption parameters without
// performing any encryption, so the endpoint can refuse a request it cannot
// answer before it issues a credential it would then have to throw away.
func (p *CredentialResponseEncryption) Validate() error {
	if p == nil {
		return nil
	}
	if _, _, err := p.recipientKey(); err != nil {
		return err
	}
	if !contains(ResponseEncryptionEncValuesSupported, p.Enc) {
		return &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("unsupported credential_response_encryption.enc %q; this Credential Issuer supports %v", p.Enc, ResponseEncryptionEncValuesSupported),
		}
	}
	if p.Zip != "" && !contains(ResponseEncryptionZipValuesSupported, p.Zip) {
		return &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("unsupported credential_response_encryption.zip %q; this Credential Issuer supports %v", p.Zip, ResponseEncryptionZipValuesSupported),
		}
	}
	return nil
}

// recipientKey parses the wallet's jwk and returns it together with the key
// management algorithm to use. §8.3 requires the JWK to carry an alg and the
// JWE to use that same alg, so the algorithm is read off the key rather than
// chosen by us.
func (p *CredentialResponseEncryption) recipientKey() (jwk.Key, jwa.KeyEncryptionAlgorithm, error) {
	empty := jwa.EmptyKeyEncryptionAlgorithm()

	if len(p.JWK) == 0 {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "credential_response_encryption.jwk is required",
		}
	}

	key, err := jwk.ParseKey(p.JWK)
	if err != nil {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "credential_response_encryption.jwk is not a well-formed JWK",
		}
	}
	if err := key.Validate(); err != nil {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "credential_response_encryption.jwk is not a valid JWK",
		}
	}

	alg, ok := key.Algorithm()
	if !ok || alg.String() == "" {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "credential_response_encryption.jwk must carry an alg parameter",
		}
	}
	if !contains(ResponseEncryptionAlgValuesSupported, alg.String()) {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("unsupported credential_response_encryption.jwk alg %q; this Credential Issuer supports %v", alg.String(), ResponseEncryptionAlgValuesSupported),
		}
	}

	return key, jwa.NewKeyEncryptionAlgorithm(alg.String()), nil
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
