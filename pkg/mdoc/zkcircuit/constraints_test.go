package zkcircuit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// circuit is a terse descriptor builder for the tables below.
func circuit(id, system, status string, docTypes []string, params map[string]any) CircuitDescriptor {
	return CircuitDescriptor{
		ID:        id,
		System:    system,
		Status:    status,
		DocTypes:  docTypes,
		Published: true,
		Params:    params,
	}
}

const mDL = "org.iso.18013.5.1.mDL"

// The live catalog publishes every vega-mc param as a STRING - "saltBytes":
// "32" - while the longfellow entries use JSON numbers. A consumer reading
// only numbers sees no constraint at all and sizes the salt from its own
// default, which is the exact failure this whole path exists to prevent.
func TestParamIntReadsTheCatalogsStringShape(t *testing.T) {
	d := circuit("vega", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": "32"})

	got, ok := d.ParamInt(ParamSaltBytes)
	if !ok || got != 32 {
		t.Fatalf(`ParamInt("saltBytes") = %d, %v; want 32, true`, got, ok)
	}
}

func TestParamIntRefusesMalformedStrings(t *testing.T) {
	for _, raw := range []string{"", " 32 ", "32.0", "0x20", "32px", "+-1"} {
		t.Run(raw, func(t *testing.T) {
			d := CircuitDescriptor{Params: map[string]any{"k": raw}}
			if got, ok := d.ParamInt("k"); ok {
				t.Fatalf("ParamInt(%q) = %d, true; want absent", raw, got)
			}
		})
	}
}

func TestActiveCircuits(t *testing.T) {
	m := &Manifest{Circuits: []CircuitDescriptor{
		circuit("active-mdl", "vega-mc", StatusActive, []string{mDL}, nil),
		circuit("deprecated", "vega-mc", "deprecated", []string{mDL}, nil),
		circuit("other-system", "longfellow", StatusActive, []string{mDL}, nil),
		circuit("other-doctype", "vega-mc", StatusActive, []string{"eu.europa.ec.eudi.pid.1"}, nil),
		circuit("no-doctypes", "vega-mc", StatusActive, nil, nil),
		circuit("no-status", "vega-mc", "", []string{mDL}, nil),
		{ID: "unpublished", System: "vega-mc", Status: StatusActive, DocTypes: []string{mDL}},
	}}

	got := m.ActiveCircuits("vega-mc", mDL)
	if len(got) != 1 || got[0].ID != "active-mdl" {
		ids := make([]string, len(got))
		for i, c := range got {
			ids[i] = c.ID
		}
		t.Fatalf("ActiveCircuits = %v, want [active-mdl]", ids)
	}

	// An unscoped entry - one declaring no docTypes - is skipped when a
	// doctype is ASKED FOR, which is the only way constraint resolution
	// ever calls this: "declares no document type" is the catalog not
	// having said, and reading that as "every document type" is how a
	// constraint meant for an mDL gets applied to something else. With no
	// doctype asked for there is nothing to narrow against, so it appears.
	all := m.ActiveCircuits("vega-mc", "")
	var sawUnscoped bool
	for _, c := range all {
		if c.ID == "no-doctypes" {
			sawUnscoped = true
		}
	}
	if !sawUnscoped {
		t.Error("an unfiltered listing should include a circuit that declares no doctypes")
	}
}

// The resolution path always asks for a doctype, so the skip above is what
// it actually gets: a circuit that never says what it is for cannot supply
// a constraint for an mDL.
func TestConstraintsIgnoresACircuitThatDeclaresNoDocType(t *testing.T) {
	m := &Manifest{Circuits: []CircuitDescriptor{
		circuit("unscoped", "vega-mc", StatusActive, nil, map[string]any{"saltBytes": "32"}),
	}}

	if _, err := m.Constraints("vega-mc", mDL); !errors.Is(err, ErrNoActiveCircuit) {
		t.Fatalf("error = %v, want ErrNoActiveCircuit", err)
	}
}

func TestConstraints(t *testing.T) {
	tests := map[string]struct {
		circuits  []CircuitDescriptor
		wantSalt  int
		wantErr   string
		wantIsErr error
	}{
		"reads the published salt": {
			circuits: []CircuitDescriptor{
				circuit("vega-r12-prover", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": "32"}),
				circuit("vega-r12-verifier", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": "32"}),
			},
			wantSalt: 32,
		},
		"a system that publishes none states no constraint": {
			circuits: []CircuitDescriptor{
				circuit("lf-1", "vega-mc", StatusActive, []string{mDL}, map[string]any{"num_attributes": float64(2)}),
			},
			wantSalt: 0,
		},
		"no active circuit refuses": {
			circuits: []CircuitDescriptor{
				circuit("vega-r11", "vega-mc", "deprecated", []string{mDL}, map[string]any{"saltBytes": "32"}),
			},
			wantIsErr: ErrNoActiveCircuit,
		},
		"active circuits that disagree refuse": {
			circuits: []CircuitDescriptor{
				circuit("vega-a", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": "32"}),
				circuit("vega-b", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": "16"}),
			},
			wantErr: "disagree about saltBytes: 16 (vega-b) vs 32 (vega-a)",
		},
		"below the accepted range refuses": {
			circuits: []CircuitDescriptor{
				circuit("tiny", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": MinSaltBytes - 1}),
			},
			wantErr: "outside the accepted range",
		},
		"above the accepted range refuses": {
			circuits: []CircuitDescriptor{
				circuit("huge", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": "1000000000"}),
			},
			wantErr: "outside the accepted range",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := (&Manifest{Circuits: tc.circuits}).Constraints("vega-mc", mDL)

			switch {
			case tc.wantIsErr != nil:
				if !errors.Is(err, tc.wantIsErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantIsErr)
				}
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
				}
			default:
				if err != nil {
					t.Fatalf("Constraints() error = %v", err)
				}
				if got.SaltBytes != tc.wantSalt {
					t.Errorf("SaltBytes = %d, want %d", got.SaltBytes, tc.wantSalt)
				}
			}
		})
	}
}

func TestSaltBytesAcrossSystems(t *testing.T) {
	// Mirrors the live catalog's shape: vega publishes a salt length,
	// longfellow publishes none and is served by the default sizing.
	m := &Manifest{Circuits: []CircuitDescriptor{
		circuit("vega-r12", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": "32"}),
		circuit("lf-8-2", "longfellow", StatusActive, []string{mDL}, map[string]any{"num_attributes": float64(2)}),
		circuit("other", "other-system", StatusActive, []string{mDL}, map[string]any{"saltBytes": float64(16)}),
	}}

	t.Run("one system", func(t *testing.T) {
		got, err := m.SaltBytes([]string{"vega-mc"}, mDL)
		if err != nil || got != 32 {
			t.Fatalf("SaltBytes = %d, %v; want 32, nil", got, err)
		}
	})

	// The case this got WRONG first time round, and the one worth the
	// longest comment. "Publishes no saltBytes" is not "any length will
	// do": zk-cred-longfellow constrains the TOTAL IssuerSignedItem size
	// (~119 bytes), which is why this package sizes salts per element - 16
	// for a claim, 8 for pseudonym_seed, whose value is itself 32 bytes.
	// Giving every item Vega's uniform 32 blows that ceiling for exactly
	// the items the smaller default exists for. Resolving such a schema to
	// 32 would mint credentials that fail Longfellow verification, which
	// is the failure this whole path exists to stop.
	t.Run("a system needing default sizing cannot be combined with one that fixes a length", func(t *testing.T) {
		_, err := m.SaltBytes([]string{"longfellow", "vega-mc"}, mDL)
		if err == nil {
			t.Fatal("expected a refusal, not a resolved length")
		}
		if !strings.Contains(err.Error(), "longfellow") || !strings.Contains(err.Error(), "32 (vega-mc)") {
			t.Fatalf("error = %v, want one naming both sides of the conflict", err)
		}
	})

	t.Run("no constraint anywhere leaves the default sizing", func(t *testing.T) {
		got, err := m.SaltBytes([]string{"longfellow"}, mDL)
		if err != nil || got != 0 {
			t.Fatalf("SaltBytes = %d, %v; want 0, nil", got, err)
		}
	})

	t.Run("systems that want different lengths refuse", func(t *testing.T) {
		_, err := m.SaltBytes([]string{"vega-mc", "other-system"}, mDL)
		if err == nil || !strings.Contains(err.Error(), "16 (other-system) vs 32 (vega-mc)") {
			t.Fatalf("error = %v, want one naming both systems and both lengths", err)
		}
	})

	t.Run("an unknown system refuses rather than resolving to nothing", func(t *testing.T) {
		_, err := m.SaltBytes([]string{"vega-mc", "nonesuch"}, mDL)
		if !errors.Is(err, ErrNoActiveCircuit) {
			t.Fatalf("error = %v, want ErrNoActiveCircuit", err)
		}
	})

	t.Run("naming no system at all refuses", func(t *testing.T) {
		if _, err := m.SaltBytes(nil, mDL); err == nil {
			t.Fatal("expected an error when no system is named")
		}
	})
}

// countingClient serves a fixed manifest body and counts fetches, so a
// test can tell a cache hit from a round trip.
type countingClient struct {
	*Client
	fetches int
	fail    bool
}

func newCountingClient(body string) *countingClient {
	cc := &countingClient{}
	cc.Client = &Client{
		Sources: []string{"https://catalog.example"},
		FetchText: func(context.Context, string) (string, error) {
			cc.fetches++
			if cc.fail {
				return "", errors.New("catalog unreachable")
			}
			return body, nil
		},
	}
	return cc
}

const oneVegaCircuit = `{"circuits":[{"id":"vega-r12","system":"vega-mc","status":"active","published":true,` +
	`"docTypes":["org.iso.18013.5.1.mDL"],"params":{"saltBytes":"32"}}]}`

func TestResolverCachesWithinTheTTL(t *testing.T) {
	cc := newCountingClient(oneVegaCircuit)
	now := time.Now()
	r := &Resolver{Client: cc.Client, TTL: time.Hour, Now: func() time.Time { return now }}

	for range 5 {
		salt, stale, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL)
		if err != nil || stale || salt != 32 {
			t.Fatalf("SaltBytes = %d, stale=%v, %v", salt, stale, err)
		}
	}
	if cc.fetches != 1 {
		t.Errorf("fetches = %d, want 1 - issuance must not be a catalog round trip per credential", cc.fetches)
	}

	now = now.Add(time.Hour + time.Second)
	if _, _, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL); err != nil {
		t.Fatal(err)
	}
	if cc.fetches != 2 {
		t.Errorf("fetches = %d, want 2 after the TTL expired", cc.fetches)
	}
}

func TestResolverServesTheLastManifestWhenARefreshFails(t *testing.T) {
	cc := newCountingClient(oneVegaCircuit)
	now := time.Now()
	r := &Resolver{Client: cc.Client, TTL: time.Minute, Now: func() time.Time { return now }}

	if _, stale, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL); err != nil || stale {
		t.Fatalf("first resolve: stale=%v, %v", stale, err)
	}

	cc.fail = true
	now = now.Add(time.Hour)

	salt, stale, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL)
	if err != nil {
		t.Fatalf("a brief catalog outage must not stop issuance: %v", err)
	}
	if !stale {
		t.Error("stale = false, want true - the caller has to be able to say so")
	}
	if salt != 32 {
		t.Errorf("SaltBytes = %d, want 32", salt)
	}
}

// The one thing the resolver will not do is answer from nothing: a
// credential sized by a guess fails in the wallet's hands at presentation
// time, with an error that says nothing about why.
func TestResolverRefusesWithNothingCached(t *testing.T) {
	cc := newCountingClient(oneVegaCircuit)
	cc.fail = true
	r := &Resolver{Client: cc.Client}

	if _, _, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL); err == nil {
		t.Fatal("expected an error when the catalog has never been reached")
	}
}

// A failed refresh must not leave the manifest expired, or every
// subsequent issuance attempts its own fetch - while holding the
// resolver's mutex, which makes the refresh single-flight on the happy
// path. One unreachable catalog then serializes every credential behind a
// 30-second HTTP timeout, which is the cache amplifying the outage it
// exists to absorb.
func TestResolverBacksOffAfterAFailedRefresh(t *testing.T) {
	cc := newCountingClient(oneVegaCircuit)
	now := time.Now()
	r := &Resolver{
		Client: cc.Client, TTL: time.Minute, RetryInterval: 5 * time.Minute,
		Now: func() time.Time { return now },
	}

	if _, _, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL); err != nil {
		t.Fatal(err)
	}
	cc.fail = true
	now = now.Add(2 * time.Minute) // past the TTL

	for range 5 {
		if _, stale, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL); err != nil || !stale {
			t.Fatalf("stale=%v, %v; want a stale answer, not a failure", stale, err)
		}
	}
	if cc.fetches != 2 {
		t.Errorf("fetches = %d, want 2 - one success and ONE failed retry, not one per call", cc.fetches)
	}

	// Past the retry interval, it tries again.
	now = now.Add(6 * time.Minute)
	if _, _, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL); err != nil {
		t.Fatal(err)
	}
	if cc.fetches != 3 {
		t.Errorf("fetches = %d, want 3 after the retry interval elapsed", cc.fetches)
	}

	// And once it succeeds again, the answer stops being stale.
	cc.fail = false
	now = now.Add(6 * time.Minute)
	if _, stale, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL); err != nil || stale {
		t.Fatalf("stale=%v, %v; want a fresh answer once the catalog is back", stale, err)
	}
}

// The same incompatibility SaltBytes refuses across systems, one level
// down: within ONE system, an active circuit publishing no saltBytes next
// to one that publishes 32. Skipping the unconstrained one resolved to 32
// and minted credentials that fail against it.
func TestConstraintsRefusesAMixedSetWithinOneSystem(t *testing.T) {
	m := &Manifest{Circuits: []CircuitDescriptor{
		circuit("vega-fixed", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": "32"}),
		circuit("vega-default", "vega-mc", StatusActive, []string{mDL}, map[string]any{"numClaims": "4"}),
	}}

	_, err := m.Constraints("vega-mc", mDL)
	if err == nil {
		t.Fatal("expected a refusal, not a resolved length")
	}
	if !strings.Contains(err.Error(), "vega-default") || !strings.Contains(err.Error(), "32 (vega-fixed)") {
		t.Fatalf("error = %v, want one naming both sides", err)
	}
}

// ... and the unmixed cases still resolve, so this is a refusal of the
// combination rather than of an absent value.
func TestConstraintsResolvesAnUnmixedSet(t *testing.T) {
	allFixed := &Manifest{Circuits: []CircuitDescriptor{
		circuit("a", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": "32"}),
		circuit("b", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": float64(32)}),
	}}
	got, err := allFixed.Constraints("vega-mc", mDL)
	if err != nil || got.SaltBytes != 32 {
		t.Fatalf("SaltBytes = %d, %v; want 32, nil", got.SaltBytes, err)
	}

	allDefault := &Manifest{Circuits: []CircuitDescriptor{
		circuit("a", "longfellow", StatusActive, []string{mDL}, map[string]any{"num_attributes": float64(1)}),
		circuit("b", "longfellow", StatusActive, []string{mDL}, map[string]any{"num_attributes": float64(2)}),
	}}
	got, err = allDefault.Constraints("longfellow", mDL)
	if err != nil || got.SaltBytes != 0 {
		t.Fatalf("SaltBytes = %d, %v; want 0, nil", got.SaltBytes, err)
	}
}

// ParamInt returns false for an absent key AND for one it cannot read, and
// those are opposites: absent means no constraint, malformed means a
// constraint nobody can honour. Reading the second as the first falls back
// to the package default and mints credentials this very circuit cannot
// verify - a fail-OPEN, in the one place that must not have one.
func TestConstraintsRefusesAMalformedSaltBytes(t *testing.T) {
	for name, value := range map[string]any{
		"a decimal string": "32.0",
		"a fractional":     2.5,
		"an object":        map[string]any{"bytes": 32},
		"an array":         []any{32},
		"a boolean":        true,
		"null":             nil,
		"an empty string":  "",
		"a padded string":  " 32 ",
		"hex":              "0x20",
	} {
		t.Run(name, func(t *testing.T) {
			m := &Manifest{Circuits: []CircuitDescriptor{
				circuit("vega-r12", "vega-mc", StatusActive, []string{mDL}, map[string]any{"saltBytes": value}),
			}}

			got, err := m.Constraints("vega-mc", mDL)
			if err == nil {
				t.Fatalf("Constraints() = %d, nil; want a refusal", got.SaltBytes)
			}
			if !strings.Contains(err.Error(), "not an integer") {
				t.Fatalf("error = %v, want it refused as malformed rather than as something else", err)
			}
		})
	}
}

// ... and a circuit with no saltBytes key at all is still the legitimate
// "no constraint" case, so this is a refusal of malformed values, not of
// Longfellow.
func TestConstraintsAcceptsAnAbsentSaltBytes(t *testing.T) {
	m := &Manifest{Circuits: []CircuitDescriptor{
		circuit("lf-8-2", "longfellow", StatusActive, []string{mDL}, map[string]any{"num_attributes": float64(2)}),
	}}

	got, err := m.Constraints("longfellow", mDL)
	if err != nil {
		t.Fatalf("Constraints() error = %v", err)
	}
	if got.SaltBytes != 0 {
		t.Errorf("SaltBytes = %d, want 0", got.SaltBytes)
	}
}

// A COLD failure - nothing cached - was not backed off at all, so every
// issuance took the mutex in turn and repeated the client's 30-second
// fetch. One unreachable catalog serialized the whole deployment behind
// one timeout after another, including schemas that pin zk_salt_bytes:
// resolveZkSaltBytes falls back to the pin only after the error arrives,
// so they paid the full wait for an answer they already had.
func TestResolverBacksOffWhenItHasNeverReachedTheCatalog(t *testing.T) {
	cc := newCountingClient(oneVegaCircuit)
	cc.fail = true
	now := time.Now()
	r := &Resolver{
		Client: cc.Client, TTL: time.Minute, RetryInterval: 5 * time.Minute,
		Now: func() time.Time { return now },
	}

	for range 5 {
		if _, _, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL); err == nil {
			t.Fatal("expected the cold failure to be reported")
		}
	}
	if cc.fetches != 1 {
		t.Errorf("fetches = %d, want 1 - the others must replay the remembered failure", cc.fetches)
	}

	// Past the retry interval it tries again...
	now = now.Add(6 * time.Minute)
	if _, _, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL); err == nil {
		t.Fatal("expected the retry to fail too")
	}
	if cc.fetches != 2 {
		t.Errorf("fetches = %d, want 2 after the retry interval elapsed", cc.fetches)
	}

	// ... and once the catalog is back, it answers and stops replaying.
	cc.fail = false
	now = now.Add(6 * time.Minute)
	salt, stale, err := r.SaltBytes(t.Context(), []string{"vega-mc"}, mDL)
	if err != nil || stale || salt != 32 {
		t.Fatalf("SaltBytes = %d, stale=%v, %v; want 32, false, nil", salt, stale, err)
	}
}
