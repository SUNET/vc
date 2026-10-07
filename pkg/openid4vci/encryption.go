package openid4vci

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwe/jwebb"
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

	// a256kwKeySize is the length in bytes of the key-wrapping key the
	// Concat KDF produces for AlgECDHESA256KW. RFC 7518 §4.6.2 feeds it to
	// the KDF as SuppPubInfo, in bits.
	a256kwKeySize = 32

	// a256gcmKeySize is the length in bytes of the content encryption key
	// EncA256GCM takes.
	a256gcmKeySize = 32
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
	// keys are the key-agreement keys used to decrypt requests, indexed by
	// kid (their RFC 7638 thumbprints), so a wallet can name the key it
	// encrypted to and rotation is adding a key rather than a flag day.
	//
	// A map rather than a jwk.Set because a key held in an HSM has no
	// private JWK to put in one: what the issuer holds is the ability to
	// perform an agreement, not the number.
	keys map[string]KeyAgreementKey

	// publicJWKS is the serialized public half, published in metadata.
	// Rendered once: it is the same bytes on every metadata request.
	publicJWKS json.RawMessage

	requestRequired  bool
	responseRequired bool
}

// NewCredentialEncryption builds the encrypter from the issuer's private
// key-agreement keys.
//
// A key is either an ECDSA P-256 private key read from a file or something
// that implements KeyAgreementKey, which is how a key held in a PKCS#11
// token arrives. Anything else is refused here rather than at the first
// request: the metadata would otherwise advertise a capability the endpoint
// does not have.
func NewCredentialEncryption(keys []crypto.PrivateKey, requestRequired, responseRequired bool) (*CredentialEncryption, error) {
	if len(keys) == 0 {
		if requestRequired || responseRequired {
			return nil, fmt.Errorf("credential encryption is required but no encryption key is configured")
		}
		return nil, nil
	}

	agreement := map[string]KeyAgreementKey{}
	public := jwk.NewSet()

	for i, raw := range keys {
		var (
			key KeyAgreementKey
			err error
		)
		switch typed := raw.(type) {
		case *ecdsa.PrivateKey:
			key, err = NewSoftwareKeyAgreementKey(typed)
		case KeyAgreementKey:
			key = typed
		default:
			return nil, fmt.Errorf("credential encryption key %d: want an ECDSA P-256 private key or a KeyAgreementKey, got %T", i, raw)
		}
		if err != nil {
			return nil, fmt.Errorf("credential encryption key %d: %w", i, err)
		}

		ec := key.PublicKey()
		if ec == nil {
			return nil, fmt.Errorf("credential encryption key %d: no public key", i)
		}
		if ec.Curve != elliptic.P256() {
			return nil, fmt.Errorf("credential encryption key %d: want curve P-256, got %s", i, ec.Curve.Params().Name)
		}

		pub, err := jwk.Import(ec)
		if err != nil {
			return nil, fmt.Errorf("credential encryption key %d: %w", i, err)
		}

		// kid is the RFC 7638 thumbprint, so it is stable across re-encodings
		// of the same key and says nothing an operator has to keep in sync.
		// Taken from the public half, which RFC 7638 §3.2 makes the same
		// number either way: the private exponent is not one of the required
		// members that get hashed.
		sum, err := pub.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("credential encryption key %d: thumbprint: %w", i, err)
		}
		kid := base64.RawURLEncoding.EncodeToString(sum)
		if _, seen := agreement[kid]; seen {
			return nil, fmt.Errorf("credential encryption key %d is a duplicate of an earlier key (kid %s)", i, kid)
		}
		agreement[kid] = key

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
		keys:             agreement,
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
func (e *CredentialEncryption) Enabled() bool { return e != nil && len(e.keys) > 0 }

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

	// Compact serialization only, and checked before anything is parsed.
	// §8.3 says the message MUST be encoded as a JWT, which is the compact
	// form; jwe.Parse also accepts the JSON serialization, where a per-
	// recipient header can carry parameters the protected header does not -
	// zip among them, which would put a compressed payload past the check
	// below and into the decrypter. Refusing the JSON form closes that
	// whole class rather than chasing one member of it.
	if !isCompactJWE(body) {
		return nil, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "the request must use JWE compact serialization",
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
	// RFC 7516 §4.1.13, via RFC 7515 §4.1.11: a recipient MUST reject a JWE
	// whose crit list names an extension it does not understand. This
	// Credential Issuer understands none, so any crit at all is refused -
	// including an empty list, which §4.1.11 makes invalid in its own right.
	//
	// Not inherited from the library. jwx only performs this check when
	// asked, with jwe.WithCritValidation(true), and the default is off for
	// compatibility with v3.0.13 and earlier - so the jwe.Decrypt call this
	// replaced did not do it either. The check is new here, not restored.
	if _, ok := headers.Critical(); ok {
		return nil, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "this Credential Issuer understands no critical JWE header extensions",
		}
	}

	plaintext, err := e.decryptECDHES(body, headers)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// decryptECDHES performs the ECDH-ES+A256KW / A256GCM decryption of a
// compact JWE, given its already-validated protected headers.
//
// This is jwe.Decrypt's job, and jwe.Decrypt is not used: it reaches
// jwebb.DeriveECDHES, which needs a concrete *ecdh.PrivateKey to call ECDH
// on, and a key in an HSM will never be one. Everything a key is asked for
// here is reduced to KeyAgreementKey.ECDH - a shared secret Z for an
// ephemeral public key - which a file key and a PKCS#11 token can both
// answer. The rest (RFC 7518 §4.6.2 Concat KDF, RFC 3394 unwrap, AES-GCM)
// is the same arithmetic in both cases, and writing it once is what keeps
// the two from drifting.
//
// Only ECDH-ES+A256KW over P-256 with A256GCM; DecryptRequest has already
// refused anything else, and this would not know what to do with it.
//
// Every failure below returns the same description. The caller is an
// unauthenticated endpoint, and telling it which step failed - a kid that
// does not resolve, an unwrap that did not authenticate, a tag that did not
// match - hands it an oracle for free.
func (e *CredentialEncryption) decryptECDHES(body []byte, headers jwe.Headers) ([]byte, error) {
	refuse := func() error {
		return &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "the request could not be decrypted with any of this Credential Issuer's keys",
		}
	}

	// The wallet must name the key it encrypted to. Every key this issuer
	// publishes carries a kid, so a request without one was not built from
	// this issuer's metadata. (jwe.Decrypt spells this WithRequireKid.)
	kid, ok := headers.KeyID()
	if !ok || kid == "" {
		return nil, refuse()
	}
	key, ok := e.keys[kid]
	if !ok {
		return nil, refuse()
	}

	epk, err := ephemeralPublicKey(headers)
	if err != nil {
		return nil, refuse()
	}

	// The five compact segments, re-split here rather than taken off the
	// parsed message: the AAD of a compact JWE is the protected header
	// exactly as it was transmitted, and re-serializing the parsed headers
	// would not reliably reproduce those bytes.
	segments := bytes.Split(body, []byte("."))
	if len(segments) != 5 {
		return nil, refuse()
	}
	aad := segments[0]
	encryptedKey, err := base64.RawURLEncoding.DecodeString(string(segments[1]))
	if err != nil {
		return nil, refuse()
	}
	iv, err := base64.RawURLEncoding.DecodeString(string(segments[2]))
	if err != nil {
		return nil, refuse()
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(string(segments[3]))
	if err != nil {
		return nil, refuse()
	}
	tag, err := base64.RawURLEncoding.DecodeString(string(segments[4]))
	if err != nil {
		return nil, refuse()
	}

	apu, _ := headers.AgreementPartyUInfo()
	apv, _ := headers.AgreementPartyVInfo()

	z, err := key.ECDH(epk)
	if err != nil {
		return nil, refuse()
	}

	// RFC 7518 §4.6.2: for a key-wrapping variant the AlgorithmID is the
	// "alg" value and the key length is the wrapping key's, not the content
	// encryption key's.
	kek := concatKDF(crypto.SHA256, z, []byte(AlgECDHESA256KW), apu, apv, a256kwKeySize)

	// RFC 3394 key unwrap, which also authenticates: a KEK derived from the
	// wrong Z fails here rather than producing a wrong CEK.
	cek, err := jwebb.KeyDecryptAESKW(nil, encryptedKey, AlgECDHESA256KW, kek)
	if err != nil {
		return nil, refuse()
	}
	// The unwrapped key is as long as whatever was wrapped, and aes.NewCipher
	// would accept 16 or 24 bytes as happily as 32 - decrypting with AES-128
	// under a header that says A256GCM. The header has already been checked
	// against EncA256GCM, so the key has to match it.
	if len(cek) != a256gcmKeySize {
		return nil, refuse()
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, refuse()
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, refuse()
	}
	// Checked rather than left to Open, which panics on a nonce of the wrong
	// length - and the length here came off the wire.
	if len(iv) != aead.NonceSize() {
		return nil, refuse()
	}

	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	plaintext, err := aead.Open(nil, iv, sealed, aad)
	if err != nil {
		return nil, refuse()
	}

	return plaintext, nil
}

// ephemeralPublicKey reads the epk header as a P-256 public key.
//
// The *ecdh.PublicKey it returns is the validation: constructing one runs
// the on-curve check, without which an invalid-curve attack recovers the
// issuer's private key one agreement at a time. A key-agreement
// implementation that forwards the point to an HSM has no later chance to
// do this, so it happens once, here, for every key type.
func ephemeralPublicKey(headers jwe.Headers) (*ecdh.PublicKey, error) {
	epk, ok := headers.EphemeralPublicKey()
	if !ok || epk == nil {
		return nil, fmt.Errorf("no epk header")
	}
	if _, isPrivate := epk.(jwk.ECDSAPrivateKey); isPrivate {
		return nil, fmt.Errorf("epk is a private key")
	}
	var pub ecdsa.PublicKey
	if err := jwk.Export(epk, &pub); err != nil {
		return nil, fmt.Errorf("epk is not an EC public key: %w", err)
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("epk is not on P-256")
	}
	return pub.ECDH()
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
	if p.Enc == "" {
		return &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "credential_response_encryption.enc is required",
		}
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

	// Validate checks the key's internal structure, not whether it can do
	// what its alg says. A well-formed RSA key carrying alg
	// ECDH-ES+A256KW passes it, and the mismatch would then surface from
	// jwe.Encrypt - after the credential had been issued. ECDH-ES needs an
	// EC key on the curve this issuer performs, so that is checked here,
	// before anything is made.
	// A private EC JWK satisfies jwk.ECDSAPublicKey structurally - it exposes
	// Crv, X and Y too - so it has to be ruled out by name. §8.2 asks for "a
	// single public key"; a wallet that sent its private key would have this
	// issuer hold key material it has no business holding, and the mistake
	// should be told to the wallet rather than quietly worked around.
	if _, isPrivate := key.(jwk.ECDSAPrivateKey); isPrivate {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: "credential_response_encryption.jwk must be a public key",
		}
	}

	ec, ok := key.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("credential_response_encryption.jwk must be an EC public key for %s, got kty %q", AlgECDHESA256KW, key.KeyType()),
		}
	}
	if crv, ok := ec.Crv(); !ok || crv != jwa.P256() {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("credential_response_encryption.jwk must use curve %s, got %q", jwa.P256(), crv),
		}
	}

	// RFC 7517 §4.2: use says what the key may be used for. jwe.Encrypt is
	// handed this key explicitly and does not consult it, so a wallet that
	// sent a signing key would get a credential encrypted to a key its own
	// library may then refuse to decrypt with - after issuance, which is
	// the one place this package tries never to fail. Absent is fine: use
	// is optional, and omitting it claims nothing.
	if use, ok := key.KeyUsage(); ok && use != "" && use != "enc" {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("credential_response_encryption.jwk declares use %q; it must be enc, or absent", use),
		}
	}

	// RFC 7517 §4.3: key_ops is use at a finer grain, and is equally
	// binding - "the operation(s) for which the key is intended to be
	// used". It is checked separately rather than derived from use: §4.3
	// says the two SHOULD NOT both appear, so a key is likely to carry one
	// or the other, and a key carrying only key_ops would otherwise be
	// unchecked.
	if ops, ok := key.KeyOps(); ok && len(ops) > 0 && !admitsKeyAgreement(ops) {
		return nil, empty, &Error{
			Err:              ErrInvalidEncryptionParameters,
			ErrorDescription: fmt.Sprintf("credential_response_encryption.jwk declares key_ops %v, none of which permit %s; it must admit one of %v, or be absent", ops, AlgECDHESA256KW, keyAgreementKeyOps),
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

// keyAgreementKeyOps are the key_ops values that admit what vc does with a
// wallet's response encryption key.
//
// What is actually performed with this key is ECDH-ES key agreement, so
// deriveKey is the exact answer and the one to reach for. The other three
// are tolerated rather than required, because RFC 7517 §4.3's vocabulary
// does not have a word for "JWE recipient key" and implementations label
// the same role differently: wrapKey describes the AES-256 key wrap the
// agreement feeds, encrypt is the coarse-grained version of the same
// claim, and deriveBits is deriveKey for libraries that only expose raw
// output. Refusing those would reject wallets that have said nothing wrong.
//
// What is refused is a key that admits none of them - a key_ops of
// ["sign"], ["verify"], ["decrypt"] or ["unwrapKey"] says this key is for
// something else, and using it anyway would hand a wallet a credential
// encrypted to a key its own library may refuse to touch. After issuance,
// which is the one place this package tries never to fail.
var keyAgreementKeyOps = []jwk.KeyOperation{
	jwk.KeyOpDeriveKey,
	jwk.KeyOpDeriveBits,
	jwk.KeyOpWrapKey,
	jwk.KeyOpEncrypt,
}

func admitsKeyAgreement(ops jwk.KeyOperationList) bool {
	for _, op := range ops {
		if slices.Contains(keyAgreementKeyOps, op) {
			return true
		}
	}
	return false
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// isCompactJWE reports whether body is JWE compact serialization: five
// base64url segments separated by dots. Deliberately not "does not look like
// JSON" - a positive test cannot be talked around by whitespace or by a
// serialization nobody has thought of yet.
func isCompactJWE(body []byte) bool {
	parts := bytes.Split(body, []byte("."))
	if len(parts) != 5 {
		return false
	}
	for i, part := range parts {
		// Only the encrypted key may be empty, and that is for the direct
		// key agreement algorithms rather than the one this accepts; allowed
		// here so the refusal names the algorithm rather than the shape.
		if len(part) == 0 && i != 1 {
			return false
		}
		if _, err := base64.RawURLEncoding.DecodeString(string(part)); err != nil {
			return false
		}
	}
	return true
}
