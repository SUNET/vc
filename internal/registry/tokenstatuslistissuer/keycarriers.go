package tokenstatuslistissuer

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"
)

// Token key carrier names, spelled as registry.token_status_lists.token_key_carriers
// writes them.
const (
	carrierX5C = "x5c"
	carrierJWK = "jwk"
)

// keyCarriers is what the issued Status List Tokens actually carry their
// signing key in, after the configured carriers have been checked against the
// key material that was loaded.
type keyCarriers struct {
	// x5cBase64 is the signing chain for the JOSE "x5c" header: base64 DER,
	// leaf first, exactly as pki.KeyMaterial holds it.
	x5cBase64 []string

	// x5chainDER is the same chain as raw DER, for the COSE x5chain header.
	x5chainDER [][]byte

	// embedJWK reports whether the bare public key rides as the "jwk" header.
	embedJWK bool
}

// resolveKeyCarriers decides which carriers the issued tokens use.
//
// configured is token_key_carriers as the deployment wrote it; chain is the
// loaded signing chain (pki.KeyMaterial.Chain), empty when no chain_path is
// configured, with leaf its signing certificate (pki.KeyMaterial.Cert) and
// signingKey the public half of the key the tokens are signed with.
//
// An unset or empty list means every carrier this deployment can produce.
// That is deliberately not an error: it is what a config that never reached
// defaults.Set looks like, and the pre-existing behaviour - an embedded jwk,
// no chain - is exactly what "everything available" resolves to for a
// deployment with no chain_path.
//
// It refuses rather than returning a carrier-less result: a token with no key
// in its header cannot be verified by anything that resolves the signer from
// the token, which is every consumer this setting exists for.
func resolveKeyCarriers(configured []string, chain []string, leaf *x509.Certificate, signingKey crypto.PublicKey) (keyCarriers, error) {
	for _, name := range configured {
		if name != carrierX5C && name != carrierJWK {
			return keyCarriers{}, fmt.Errorf("unknown token key carrier %q: supported carriers are %q and %q", name, carrierX5C, carrierJWK)
		}
	}

	wantX5C, wantJWK := true, true
	if len(configured) > 0 {
		wantX5C = slices.Contains(configured, carrierX5C)
		wantJWK = slices.Contains(configured, carrierJWK)
	}

	carriers := keyCarriers{embedJWK: wantJWK}

	if wantX5C && len(chain) > 0 {
		if err := requireChainMatchesSigner(leaf, signingKey); err != nil {
			return keyCarriers{}, err
		}
		carriers.x5cBase64 = slices.Clone(chain)
		carriers.x5chainDER = make([][]byte, 0, len(chain))
		for i, encoded := range chain {
			der, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return keyCarriers{}, fmt.Errorf("signing chain certificate %d is not valid base64 DER: %w", i, err)
			}
			carriers.x5chainDER = append(carriers.x5chainDER, der)
		}
	}

	if len(carriers.x5cBase64) == 0 && !carriers.embedJWK {
		return keyCarriers{}, fmt.Errorf("token_key_carriers asks only for %q, but no signing chain is loaded: configure registry.token_status_lists.key_config.chain_path, or add %q", carrierX5C, carrierJWK)
	}

	return carriers, nil
}

// requireChainMatchesSigner refuses a chain whose leaf certificate is not the
// certificate for the key the tokens are signed with.
//
// The two are loaded independently: pki.loadKeyMaterialFromFile reads
// private_key_path and chain_path and never compares them. So a chain left
// behind by a key rotation is accepted at startup and embedded in every token,
// and it breaks precisely the consumers the x5c carrier exists for - a
// verifier that takes the signer's key from the leaf certificate derives the
// wrong key, and every signature check fails. For an x5c-only deployment that
// is every consumer, and the failure surfaces at the verifier, a long way from
// its cause.
//
// Checked here, at startup, because that is the last place the two halves are
// known to be about to be published together.
func requireChainMatchesSigner(leaf *x509.Certificate, signingKey crypto.PublicKey) error {
	// Refused rather than skipped: a chain that cannot be checked against the
	// signing key is a chain that may not belong to it.
	if leaf == nil {
		return fmt.Errorf("a signing chain is configured but carries no parsed leaf certificate, so it cannot be checked against the signing key")
	}
	if signingKey == nil {
		return fmt.Errorf("the signing key has no public half to check the signing chain's leaf certificate against")
	}

	// Every key type this repo signs with - ecdsa, rsa, ed25519, and what a
	// PKCS#11 signer returns from Public() - implements Equal.
	comparable, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("the signing chain's leaf certificate carries a %T public key, which cannot be compared with the signing key", leaf.PublicKey)
	}
	if !comparable.Equal(signingKey) {
		return fmt.Errorf("the signing chain's leaf certificate is for a different key than the configured signing key: check that key_config.chain_path and key_config.private_key_path are the same key pair")
	}
	return nil
}
