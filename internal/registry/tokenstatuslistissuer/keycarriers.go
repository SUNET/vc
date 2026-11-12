package tokenstatuslistissuer

import (
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
// configured.
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
func resolveKeyCarriers(configured []string, chain []string) (keyCarriers, error) {
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
