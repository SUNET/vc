package registry

import (
	"sync"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// Freshness describes how current a registry's data is. A zero field means
// unknown or not applicable.
type Freshness struct {
	// AsOf is when the data was last loaded.
	AsOf time.Time
	// NextUpdate is when the source says it will next be replaced.
	NextUpdate time.Time
}

// FreshnessReporter is implemented by registries that know how fresh their data
// is. It is optional: a registry without it is reported with no as_of and no
// next_update, which a caller must read as "unknown".
type FreshnessReporter interface {
	Freshness() Freshness
}

// ParseSourceTime parses a timestamp from a trust-data source (ETSI
// dateTime, VICAL/RICAL tdate). The value must carry an explicit UTC offset
// (RFC 3339). An empty, unparseable or offset-free value yields the zero time,
// i.e. "unknown": freshness must never be invented, and assuming a zone for an
// offset-free value could report a deadline later than the source meant.
func ParseSourceTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s) // also accepts RFC 3339 without fractional seconds
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// CacheFreshness reports the freshness of a fetched-and-cached list. view
// returns when the cached list was fetched and the nextUpdate it declares
// (unknown unless it parses, see ParseSourceTime). Nothing is reported before
// the first fetch, nor once the cache has outlived ttl: the next evaluation must
// refetch, and if that fails the registry keeps the old list and denies, a
// denial that can flip as soon as fetching recovers. The expiry test is the
// registries' own (fresh only while time since fetch < ttl), so a zero or
// negative ttl is always expired.
func CacheFreshness[C any](mu *sync.RWMutex, cache **C, ttl time.Duration, view func(*C) (fetchedAt time.Time, nextUpdate string)) Freshness {
	mu.RLock()
	c := *cache
	mu.RUnlock()
	if c == nil {
		return Freshness{}
	}
	fetchedAt, nextUpdate := view(c)
	if time.Since(fetchedAt) >= ttl {
		return Freshness{}
	}
	return Freshness{AsOf: fetchedAt, NextUpdate: ParseSourceTime(nextUpdate)}
}

// EarliestKnown returns the earliest of the times, or the zero time (unknown)
// when there are none or any of them is unknown. A registry that holds several
// lists can decide from any of them, so it is only as fresh as its
// soonest-expiring list, and unknown if any list is.
func EarliestKnown(times ...time.Time) time.Time {
	var earliest time.Time
	for _, t := range times {
		if t.IsZero() {
			return time.Time{}
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest
}

// trustDatum is one registry's freshness at a point in time. The times keep
// full precision so two snapshots are compared exactly, not as the rounded
// strings sent on the wire.
type trustDatum struct {
	name string
	// group is the name of the top-level registry this one was reached through:
	// itself, or the composite containing it.
	group      string
	asOf, next time.Time
}

func (d trustDatum) same(o trustDatum) bool {
	return d.name == o.name && d.asOf.Equal(o.asOf) && d.next.Equal(o.next)
}

// collectTrustData appends one entry per leaf registry under reg. A composite
// contributes its children, not itself.
func collectTrustData(reg TrustRegistry, group string, out []trustDatum) []trustDatum {
	if c, ok := reg.(*CompositeRegistry); ok {
		for _, child := range c.registries {
			out = collectTrustData(child, group, out)
		}
		return out
	}
	d := trustDatum{name: reg.Info().Name, group: group}
	if fr, ok := reg.(FreshnessReporter); ok {
		f := fr.Freshness()
		d.asOf, d.next = f.AsOf, f.NextUpdate
	}
	return append(out, d)
}

// trustDataSnapshot returns the current freshness of every registry in regs.
func trustDataSnapshot(regs []TrustRegistry) []trustDatum {
	var data []trustDatum
	for _, r := range regs {
		data = collectTrustData(r, r.Info().Name, data)
	}
	return data
}

// responseIncomplete reports whether resp says some registry behind it failed
// to answer (see CompositeRegistry).
func responseIncomplete(resp *authzen.EvaluationResponse) bool {
	if resp == nil || resp.Context == nil {
		return false
	}
	inc, _ := resp.Context.Reason["incomplete"].(bool)
	return inc
}

// failedRegistries names the registries a denial did not really come from: the
// strategy recorded an error for them (including an open circuit breaker or a
// panic) or they gave no decision. Such a denial can become an allow without
// any list changing, so its freshness is unknown. Only a denial is examined: an
// allow stands on the registry that allowed it.
func failedRegistries(resp *authzen.EvaluationResponse) map[string]bool {
	if resp == nil || resp.Decision || resp.Context == nil {
		return nil
	}
	failed := map[string]bool{}
	for _, key := range []string{"registry_results", "all_results"} {
		entries, _ := resp.Context.Reason[key].([]map[string]interface{})
		for _, e := range entries {
			name, _ := e["registry"].(string)
			_, isErr := e["error"]
			inner, _ := e["reason"].(map[string]interface{})
			nested, _ := inner["incomplete"].(bool) // a composite with a failed child
			if decided, ok := e["decision"].(bool); name != "" && (isErr || nested || !ok || decided) {
				failed[name] = true
			}
		}
	}
	return failed
}

// attachTrustData returns a copy of resp whose context carries the freshness of
// every registry that could have contributed to the decision. The copy matters:
// registries may hand back a response they also keep.
//
// before and after are snapshots taken around the evaluation. A registry may
// reload while it is being evaluated, and its freshness is read outside its own
// lock, so an entry is only reported when both snapshots agree; otherwise the
// data the decision used cannot be told apart from the data now loaded, and the
// entry carries no as_of or next_update (unknown).
//
// The set is the policy-filtered applicable registries, not only those that
// answered first. For a first-match allow that can name a registry that was not
// reached, which only makes the reported bound earlier, never later.
func attachTrustData(resp *authzen.EvaluationResponse, before, after []trustDatum) *authzen.EvaluationResponse {
	if resp == nil || len(after) == 0 {
		return resp
	}
	failed := failedRegistries(resp)
	data := make([]authzen.TrustData, len(after))
	for i, a := range after {
		data[i] = authzen.TrustData{Registry: a.name}
		if len(before) != len(after) || !before[i].same(a) || failed[a.group] {
			continue
		}
		if !a.asOf.IsZero() {
			data[i].AsOf = a.asOf.UTC().Format(time.RFC3339)
		}
		if !a.next.IsZero() {
			data[i].NextUpdate = a.next.UTC().Format(time.RFC3339)
		}
	}
	out := *resp
	var ctx authzen.EvaluationResponseContext
	if resp.Context != nil {
		ctx = *resp.Context
	}
	ctx.TrustData = data
	out.Context = &ctx
	return &out
}
