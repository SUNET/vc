package apiv1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/mdoc/zkcircuit"
)

// newZkCircuitResolver builds the catalog resolver used to size
// IssuerSignedItem salts, or nil when the deployment has configured no
// sources at all.
//
// Nil is a real configuration, not a failure: an issuer that offers no
// ZK-provable mdoc never asks, and an operator who has deliberately cut
// the issuer off from the network can say so by clearing sources and
// pinning zk_salt_bytes in the schemas that need it.
func newZkCircuitResolver(sources []string, cacheTTLSeconds int) *zkcircuit.Resolver {
	if len(sources) == 0 {
		return nil
	}
	resolver := zkcircuit.NewResolver(zkcircuit.NewClient(sources...))
	if cacheTTLSeconds > 0 {
		resolver.TTL = time.Duration(cacheTTLSeconds) * time.Second
	}
	return resolver
}

// resolveZkSaltBytes decides the IssuerSignedItem salt length for one
// issuance and returns it; the caller writes it onto the schema.
//
// The order of precedence, and why:
//
//  1. A schema that declares no zk_systems is not asking. Its
//     zk_salt_bytes - usually zero - is used as-is, which is what every
//     non-ZK mdoc in the tree does today.
//
//  2. Otherwise the catalog is the source of truth. The required length is
//     a property of the circuit build, published per circuit version, and
//     resolving it is the entire point: a hand-copied number cannot notice
//     a new circuit revision changing its mind, which is how a fleet of
//     credentials came to fail Vega verification on every claim.
//
//  3. A schema that ALSO pins zk_salt_bytes overrides the catalog, and the
//     disagreement is logged at Error. The pin is for the cases the
//     catalog cannot serve - an air-gapped issuer, or interop against a
//     circuit that is not published yet - so it has to win; what it must
//     not do is win quietly.
//
// A schema that declares a zk_system and pins nothing, where the catalog
// cannot be reached at all, REFUSES. The alternative is minting a
// credential whose salt length is a guess, and that credential fails at
// presentation time in the wallet's hands, with an error that says
// nothing about why.
func (c *Client) resolveZkSaltBytes(ctx context.Context, schema *mdoc.MDDLSchema) (int, error) {
	if len(schema.ZkSystems) == 0 {
		return schema.ZkSaltBytes, nil
	}

	if c.zkResolver == nil {
		if schema.ZkSaltBytes != 0 {
			c.log.Info("no zk-circuits source configured; using the schema's pinned salt length",
				"doctype", schema.DocType, "zk_systems", schema.ZkSystems, "zk_salt_bytes", schema.ZkSaltBytes)
			return schema.ZkSaltBytes, nil
		}
		return 0, fmt.Errorf("MDDL schema for doctype %q declares zk_systems %v but issuer.zk_circuits.sources is empty and the schema pins no zk_salt_bytes",
			schema.DocType, schema.ZkSystems)
	}

	resolved, stale, err := c.zkResolver.SaltBytes(ctx, schema.ZkSystems, schema.DocType)
	if err != nil {
		// A pin stands in only for a catalog that cannot answer: unreachable,
		// or publishing no active circuit for this system yet. A constraint
		// refusal (incompatible systems, malformed metadata) or a cancelled
		// request is a real answer, and letting a pin override it would sign a
		// credential the catalog just said must not be issued.
		pinnable := errors.Is(err, zkcircuit.ErrCatalogUnavailable) || errors.Is(err, zkcircuit.ErrNoActiveCircuit)
		if schema.ZkSaltBytes != 0 && pinnable {
			c.log.Error(err, "zk_circuit_salt_resolution_failed_using_pin",
				"doctype", schema.DocType, "zk_systems", schema.ZkSystems, "zk_salt_bytes", schema.ZkSaltBytes)
			return schema.ZkSaltBytes, nil
		}
		return 0, fmt.Errorf("resolving the salt length for doctype %q from the circuit catalog: %w", schema.DocType, err)
	}

	if stale {
		c.log.Info("zk-circuits manifest could not be refreshed; resolved from the last one fetched",
			"doctype", schema.DocType, "zk_systems", schema.ZkSystems)
	}

	if schema.ZkSaltBytes != 0 {
		if schema.ZkSaltBytes != resolved {
			c.log.Error(errZkSaltPinDisagreesWithCatalog, "zk_circuit_salt_pin_disagrees_with_catalog",
				"doctype", schema.DocType, "zk_systems", schema.ZkSystems,
				"pinned", schema.ZkSaltBytes, "catalog", resolved)
		}
		return schema.ZkSaltBytes, nil
	}

	c.log.Debug("resolved the IssuerSignedItem salt length from the circuit catalog",
		"doctype", schema.DocType, "zk_systems", schema.ZkSystems, "zk_salt_bytes", resolved)
	return resolved, nil
}

// errZkSaltPinDisagreesWithCatalog exists so the log line above carries an
// error the way logr wants one. The pin still wins - this says loudly that
// it is now doing so against the catalog's own published answer, which is
// the state a stale pin leaves behind.
var errZkSaltPinDisagreesWithCatalog = fmt.Errorf("schema's pinned zk_salt_bytes differs from the circuit catalog")
