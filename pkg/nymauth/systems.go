package nymauth

import "fmt"

// Proof systems a nym_auth circuit build can belong to, named by the
// system_id a presentation states.
//
// These are the catalog ALIASES, not the catalog ids and not the
// proofSystem names: the zk-circuits catalog gives each nym_auth mdoc
// entry an alias of this form, and that is what travels on the wire in
// zkp_req's "system_id" and in a Verifier's advertised
// system_id_values. The catalog's own id (nymauth-vega-mdoc-v1) and
// its proofSystem (vega-v1) are different strings for different jobs.
//
// The SD-JWT entries carry no alias yet, so there is nothing to name
// here for them - see
// https://github.com/SUNET/vc/issues/852.
const (
	SystemLongfellowNymAuth = "urn:circuits:longfellow:nym_auth:v1"
	SystemVegaNymAuth       = "urn:circuits:vega:nym_auth:v1"
)

// Systems names every proof system this package knows a system_id for,
// in a stable order.
func Systems() []string {
	return []string{SystemLongfellowNymAuth, SystemVegaNymAuth}
}

// CheckSystemID refuses a system_id that is not one of the above.
//
// Refused rather than passed through, for the same reason an unknown
// configuration is: a system_id selects which circuit library checks
// the proof, and a value this build cannot map to one is a statement
// about a verifier that does not exist here. Letting it through would
// defer the failure to the first presentation, where an operator sees
// a refused proof and no reason to suspect the configuration.
func CheckSystemID(systemID string) error {
	switch systemID {
	case SystemLongfellowNymAuth, SystemVegaNymAuth:
		return nil
	case "":
		return fmt.Errorf("nymauth: no system_id; it names the proof system a circuit belongs to, one of %v", Systems())
	default:
		return fmt.Errorf("nymauth: %q is not a nym_auth system_id; known ones are %v", systemID, Systems())
	}
}
