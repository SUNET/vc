package apiv1

import "github.com/SUNET/vc/pkg/openid4vp"

// filterNeverDisclose removes claims this deployment will never request
// from a query, and says so in the log when it does.
//
// Logged at INFO rather than silently, because a query arriving here with
// a blocked claim in it means something upstream asked for one - a preset
// an operator wrote, or a caller of /ui/interaction - and they will
// otherwise wonder why the claim never comes back. The log names the
// query, never the claim values.
func (c *Client) filterNeverDisclose(source string, query *openid4vp.DCQL) {
	if query == nil {
		return
	}

	neverDisclose := c.cfg.NeverDisclose()
	if neverDisclose.Empty() {
		return
	}

	before := countClaims(query)
	neverDisclose.FilterDCQL(query)
	if after := countClaims(query); after != before {
		c.log.Info("removed never-disclose claims from a DCQL query",
			"source", source, "claims_before", before, "claims_after", after)
	}
}

func countClaims(query *openid4vp.DCQL) int {
	total := 0
	for _, credential := range query.Credentials {
		total += len(credential.Claims)
	}
	return total
}
