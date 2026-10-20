package apiv1

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/google/uuid"
)

// seedHex is what a delivered seed must look like on the wire: exactly
// 32 LOWERCASE hexadecimal characters, the 16-byte seed
// (privatedata-spec SPEC 2.6 section 5A.1).
//
// Lowercase is normative, not cosmetic: the wallet decodes the string
// and compares SHA256(seed) against the credential's ssc, and a wallet
// that refuses mixed case - as the specification says it must - would
// fail the issuance on a value we considered fine.
var seedHex = regexp.MustCompile(`^[0-9a-f]{32}$`)

// maxSeedNamespaces is the most namespaces one response may carry.
const maxSeedNamespaces = 8

// maxSeedNamespaceBytes bounds a namespace name.
const maxSeedNamespaceBytes = 64

// deliverSeeds attaches the delivered seeds to the Credential Response,
// or refuses the issuance.
//
// The refusals are the specification's, and every one of them fails the
// issuance rather than degrading it:
//
//   - a plain response. The wallet has to have ASKED for encryption, so
//     an issuer that delivered anyway would put a permanent per-subject
//     secret on the wire in the clear. Degrading to "issue without the
//     seed" would be worse than failing: the wallet would store a
//     credential whose commitment it can never open, and find out only
//     when a proof is needed.
//   - no notification_id. The wallet reports a failed commitment check
//     through it; without one a mismatch is silent.
//   - a malformed seed or namespace, which a wallet refuses outright.
//
// Nothing here is persisted, cached, logged or traced. The seeds arrive
// in a map that lives for this request and the hex strings go straight
// into the response.
// checkSeedDelivery refuses a delivery this request cannot carry,
// BEFORE anything is issued.
//
// Split out from the attachment below and called immediately after the
// seeds are derived, which is before the issuer is reached. Every
// condition here is knowable then - the scope's configuration and the
// request's own credential_response_encryption - so checking it later
// bought nothing and cost a great deal: a request that was always going
// to be refused had already minted a credential, burned a status-list
// entry, written the subject's record and counted itself as issued.
//
// Those are not free. A status-list index is permanent, and a wallet
// retrying after the refusal consumes another one.
func checkSeedDelivery(seeds map[string]string, encryption *openid4vci.CredentialResponseEncryption) error {
	if len(seeds) == 0 {
		return nil
	}

	if encryption == nil {
		return &openid4vci.Error{
			Err: openid4vci.ErrInvalidCredentialRequest,
			ErrorDescription: "this credential delivers a secret seed, which is only sent in an encrypted response; " +
				"request credential_response_encryption",
		}
	}
	if len(seeds) > maxSeedNamespaces {
		return fmt.Errorf("seed delivery: %d namespaces; the wire shape allows at most %d", len(seeds), maxSeedNamespaces)
	}
	for namespace, value := range seeds {
		switch {
		case namespace == "":
			return fmt.Errorf("seed delivery: a namespace with no name")
		case len(namespace) > maxSeedNamespaceBytes:
			return fmt.Errorf("seed delivery: namespace %q is %d bytes; at most %d", namespace, len(namespace), maxSeedNamespaceBytes)
		case namespace == model.SeedNamespacesMember:
			// Reserved for the advertisement. A response carrying it
			// would be indistinguishable from an issuer-metadata entry,
			// and the specification calls each malformed in the other's
			// place.
			return fmt.Errorf("seed delivery: %q is reserved for the issuer-metadata advertisement and cannot be a namespace", namespace)
		case !seedHex.MatchString(value):
			// The VALUE is never in this error. It is the secret.
			return fmt.Errorf("seed delivery: the seed for namespace %q is not 32 lowercase hexadecimal characters", namespace)
		}
	}

	return nil
}

// deliverSeeds attaches the checked seeds to the response.
//
// It re-runs checkSeedDelivery rather than trusting that the caller
// did: this is the function that writes a secret onto the wire, and the
// one place where "someone upstream validated it" must not be an
// assumption. The checks are a handful of comparisons on a map that
// holds at most eight entries.
func (c *Client) deliverSeeds(response *openid4vci.CredentialResponse, seeds map[string]string, encryption *openid4vci.CredentialResponseEncryption) error {
	if len(seeds) == 0 {
		return nil
	}
	if err := checkSeedDelivery(seeds, encryption); err != nil {
		return err
	}

	// A notification_id is required with a delivered seed: it is how the
	// wallet reports a failed commitment check. Minted here when the
	// response has none, rather than refused, because nothing else on
	// this path sets one and refusing would make the feature
	// unreachable.
	if response.NotificationID == "" {
		response.NotificationID = uuid.NewString()
	}

	member, err := json.Marshal(seeds)
	if err != nil {
		return fmt.Errorf("seed delivery: %w", err)
	}
	if response.CredentialMetadata == nil {
		response.CredentialMetadata = &openid4vci.CredentialMetadata{}
	}
	if response.CredentialMetadata.Extensions == nil {
		response.CredentialMetadata.Extensions = map[string]json.RawMessage{}
	}
	response.CredentialMetadata.Extensions[model.SeedMetadataMember] = member
	return nil
}

// seedNamespacesForScope returns the namespaces a scope delivers, for
// the issuer-metadata advertisement.
//
// NAMES only. The advertisement exists so a wallet knows to request an
// encrypted response before it asks for the credential; it must never
// carry a value, and an issuer-metadata entry that did would be
// malformed (SPEC 2.6 section 5A.3/5A.4).
func seedNamespacesForScope(meta *model.CredentialMetadata) []string {
	if meta == nil {
		return nil
	}
	var namespaces []string
	for _, claim := range meta.Commitments {
		if claim == nil || !claim.Deliver {
			continue
		}
		namespace := claim.Namespace
		if namespace == "" {
			namespace = model.DefaultSeedNamespace
		}
		if !slices.Contains(namespaces, namespace) {
			namespaces = append(namespaces, namespace)
		}
	}
	slices.Sort(namespaces)
	return namespaces
}

// seedAdvertisement is the issuer-metadata member for these namespaces,
// or nil when the scope delivers none.
func seedAdvertisement(namespaces []string) json.RawMessage {
	if len(namespaces) == 0 {
		return nil
	}
	encoded, err := json.Marshal(map[string][]string{model.SeedNamespacesMember: namespaces})
	if err != nil {
		// Unreachable: a map of strings always encodes.
		return nil
	}
	return encoded
}

// advertiseSeedNamespaces publishes, for each credential configuration
// that delivers a seed, the NAMES of the namespaces it delivers:
//
//	"credential_metadata": {
//	  "org.siros.secret_seed": {"namespaces": ["org.siros.nym_auth"]}
//	}
//
// Names only, never a value. An issuer-metadata entry carrying
// hexadecimal seeds is malformed, and a wallet treats a malformed entry
// as if the configuration were not offered (SPEC 2.6 section 5A.3) - so
// publishing a seed here would not merely leak it, it would take the
// configuration out of service.
//
// This and the issuance-time refusal are one mechanism. The
// specification encrypts a response only when the wallet ASKED, so a
// wallet that cannot see in advance that a seed is coming has no reason
// to request credential_response_encryption, and would then be refused
// at issuance with nothing to tell it why.
func (c *Client) advertiseSeedNamespaces() error {
	if c.issuerMetadata == nil || c.cfg == nil || c.cfg.Common == nil {
		return nil
	}
	for scope, meta := range c.cfg.Common.CredentialMetadata {
		namespaces := seedNamespacesForScope(meta)
		if len(namespaces) == 0 {
			continue
		}
		config, ok := c.issuerMetadata.CredentialConfigurationsSupported[scope]
		if !ok {
			// A scope that delivers a seed but is not offered at all.
			// Refused rather than skipped: the configuration says this
			// credential hands out a permanent per-subject secret, and
			// the operator should learn that it is unreachable now
			// rather than from its absence later.
			return fmt.Errorf("scope %q configures seed delivery but is not an offered credential configuration", scope)
		}
		if config.CredentialMetadata == nil {
			config.CredentialMetadata = &openid4vci.CredentialMetadata{}
		}
		if config.CredentialMetadata.Extensions == nil {
			config.CredentialMetadata.Extensions = map[string]json.RawMessage{}
		}
		config.CredentialMetadata.Extensions[model.SeedMetadataMember] = seedAdvertisement(namespaces)
		// The map holds VALUES, not pointers: without this the
		// advertisement would be written into a copy and never
		// published, which is the kind of omission that looks like the
		// feature simply not working.
		c.issuerMetadata.CredentialConfigurationsSupported[scope] = config
		c.log.Info("Advertising seed namespaces", "scope", scope, "namespaces", namespaces)
	}
	return nil
}
