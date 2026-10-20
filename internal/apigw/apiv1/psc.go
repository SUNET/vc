package apiv1

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// pscBytes is the width of a nym_auth commitment: SHA-256 of the
// holder's private_seed.
const pscBytes = 32

// holderCommitmentsForScope names the commitments this scope expects
// the HOLDER to supply, sorted, or nil when it expects none.
func holderCommitmentsForScope(meta *model.CredentialMetadata) []string {
	if meta == nil {
		return nil
	}
	var names []string
	for _, claim := range meta.Commitments {
		if claim == nil || claim.Source != model.CommitmentSourceHolder {
			continue
		}
		// One name today. Keyed by the commitment's name rather than
		// by the claim path, because the wallet knows what a psc is
		// and does not know where this issuer writes it.
		if !slices.Contains(names, model.CommitmentPSC) {
			names = append(names, model.CommitmentPSC)
		}
	}
	slices.Sort(names)
	return names
}

// holderCommitmentsAdvertisement is the issuer-metadata member for
// these names, or nil when the scope expects none.
func holderCommitmentsAdvertisement(names []string) json.RawMessage {
	if len(names) == 0 {
		return nil
	}
	encoded, err := json.Marshal(map[string][]string{model.HolderCommitmentsListMember: names})
	if err != nil {
		// Unreachable: a map of strings always encodes.
		return nil
	}
	return encoded
}

// advertiseHolderCommitments publishes, per credential configuration
// that expects one, the NAMES of the commitments the holder supplies:
//
//	"credential_metadata": {
//	  "org.siros.holder_commitments": {"commitments": ["psc"]}
//	}
//
// Names only, never values - there is no value to publish, because the
// issuer never has one until a wallet sends it.
//
// This and the issuance-time refusal are one mechanism, exactly as for
// the seed advertisement: a wallet that cannot see the expectation has
// no reason to put the claim in its proof.
func (c *Client) advertiseHolderCommitments() error {
	if c.issuerMetadata == nil || c.cfg == nil || c.cfg.Common == nil {
		return nil
	}
	for scope, meta := range c.cfg.Common.CredentialMetadata {
		names := holderCommitmentsForScope(meta)
		if len(names) == 0 {
			continue
		}
		config, ok := c.issuerMetadata.CredentialConfigurationsSupported[scope]
		if !ok {
			// A scope expecting a holder commitment but not offered at
			// all. Refused rather than skipped, as for seed delivery:
			// the operator should learn it is unreachable now rather
			// than from its absence later.
			return fmt.Errorf("scope %q expects a holder-supplied commitment but is not an offered credential configuration", scope)
		}
		if config.CredentialMetadata == nil {
			config.CredentialMetadata = &openid4vci.CredentialMetadata{}
		}
		if config.CredentialMetadata.Extensions == nil {
			config.CredentialMetadata.Extensions = map[string]json.RawMessage{}
		}
		config.CredentialMetadata.Extensions[model.HolderCommitmentsMember] = holderCommitmentsAdvertisement(names)
		// The map holds VALUES, not pointers.
		c.issuerMetadata.CredentialConfigurationsSupported[scope] = config
		c.log.Info("Advertising holder-supplied commitments", "scope", scope, "commitments", names)
	}
	return nil
}

// pscFromProofClaims reads org.siros.psc from a proof JWT's claims.
//
// The claims MUST be ones whose signature has already been verified.
// This function cannot tell a validated claim set from a parsed one,
// which is exactly why its only caller is downstream of the proof
// verification: an unvalidated value is one the wallet did not have to
// sign, and placing a psc is the attack the proof binding exists to
// stop.
//
// Returns ("", nil) when the claim is absent, so a caller can tell
// "not sent" from "sent wrong".
func pscFromProofClaims(claims map[string]any) (string, error) {
	raw, present := claims[model.PSCProofClaim]
	if !present {
		return "", nil
	}
	encoded, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("the %s claim is not a string", model.PSCProofClaim)
	}
	// RawURLEncoding: unpadded, per RFC 7515 section 2, like every
	// other binary value in a JWT. Padding is refused rather than
	// accepted alongside, so two wallets cannot quietly disagree about
	// the encoding of a value that has to match byte for byte.
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("the %s claim is not unpadded base64url: %w", model.PSCProofClaim, err)
	}
	if len(decoded) != pscBytes {
		return "", fmt.Errorf("the %s claim is %d bytes; a commitment is %d", model.PSCProofClaim, len(decoded), pscBytes)
	}
	// Decoding is not enough: Go's decoder SKIPS CR and LF, and
	// accepts a final character whose unused low bits are not zero. So
	// a newline spliced into the middle, and "...AB" where "...AA" was
	// meant, both decode to 32 bytes - two spellings of one
	// commitment, from a wire contract that says there is one. A
	// canonical re-encoding is the cheapest way to say "exactly these
	// characters" without writing a second decoder.
	if base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return "", fmt.Errorf("the %s claim is not canonical base64url; it decodes to %d bytes that re-encode differently",
			model.PSCProofClaim, len(decoded))
	}
	return hex.EncodeToString(decoded), nil
}

// pscAcrossProofs reduces a batch's per-proof commitments to the one
// the request is making.
//
// A batch binds one credential per KEY, and a commitment is per
// SUBJECT. So every proof in a request must carry the same one, and
// two different ones is a single request claiming to be two people.
// Refused rather than resolved by taking the first, which would issue
// the whole batch against a commitment only one proof named.
//
// "Some proofs carry it and some do not" is refused for the same
// reason: it is not a request where the commitment is absent, and it
// is not one where it is present. Whichever it was read as, half the
// proofs would be saying otherwise.
func pscAcrossProofs(claims []map[string]any) (string, error) {
	var agreed string
	for i, set := range claims {
		psc, err := pscFromProofClaims(set)
		if err != nil {
			return "", err
		}
		if i == 0 {
			agreed = psc
			continue
		}
		if psc != agreed {
			return "", fmt.Errorf("the proofs carry different %s claims; a commitment is per subject, not per key", model.PSCProofClaim)
		}
	}
	return agreed, nil
}

// pscConflictError is the refusal a second, different commitment gets.
//
// invalid_credential_request, so HTTP 400, with a marked prefix the
// SDK matches on and then the sentence a person reads. Nothing is
// issued and no status-list entry is burned, because this is raised
// before the format dispatch.
func pscConflictError() *openid4vci.Error {
	return &openid4vci.Error{
		Err: openid4vci.ErrInvalidCredentialRequest,
		ErrorDescription: model.PSCConflictPrefix +
			" this subject already has a nym_auth commitment on record; " +
			"a wallet that has lost its account key needs an operator-approved reset",
	}
}
