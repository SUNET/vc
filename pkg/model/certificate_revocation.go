package model

import (
	"time"

	"github.com/SUNET/vc/pkg/revocation"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
)

// RevocationCheck configures whether vc checks one of its own certificates for revocation, and what to do about the answer.
//
// This is operational hygiene rather than a security control. An operator who
// wants to present a revoked certificate can switch it off, and a wallet
// checks independently regardless. What it buys is finding out ourselves
// instead of finding out from users, because a revoked certificate means
// wallets reject us.
//
// This type is the policy half only: it decides what a check result means.
// Nothing here runs a check. Deciding when to check - at startup, and on
// what schedule after that - belongs to each service's lifecycle, and that
// wiring is not in place yet, so configuring this today records the intended
// policy without any check being performed.
type RevocationCheck struct {
	// Mode is one of "off", "warn" or "fail".
	//
	// warn is the default, and deliberately so. An unreachable CRL or status
	// list is evidence of nothing: not that the certificate is revoked, and
	// not that it is valid. Reading it as revoked would turn a Registrar
	// outage into ours; reading it as valid would make a fetch failure a
	// silent pass. It is reported as undetermined and warn proceeds anyway,
	// while fail is available for deployments that would rather stop than
	// carry on without an answer.
	Mode string `yaml:"mode,omitempty" validate:"omitempty,oneof=off warn fail" default:"warn" doc_example:"\"warn\""`

	// RefreshInterval is how often the check should repeat after startup.
	// Revocation is a fact that changes while a process runs, so a
	// boot-time-only check goes stale. Zero disables rechecking.
	//
	// No scheduler reads this yet - see RevocationCheck. It is the interval
	// the service lifecycle will use once the checks are wired in.
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty" default:"1h" doc_example:"\"1h\""`
}

// mode returns the configured mode, defaulting to warn.
//
// An unrecognised value is treated as warn rather than off, so a typo cannot
// silently disable the check. Validation rejects one anyway; this is the
// belt to that brace.
func (r *RevocationCheck) mode() rpcert.RevocationMode {
	if r == nil || r.Mode == "" {
		return rpcert.RevocationWarn
	}
	m := rpcert.RevocationMode(r.Mode)
	if !m.Valid() {
		return rpcert.RevocationWarn
	}
	return m
}

// Enabled reports whether the check should run at all.
func (r *RevocationCheck) Enabled() bool {
	return r != nil && r.mode() != rpcert.RevocationOff
}

// Evaluate turns a check outcome into a decision.
//
// err is the checker's error, which matters as much as the status: a status
// of unknown because nothing could be fetched is a different fact from a
// clean "not revoked", and only the latter may pass silently.
func (r *RevocationCheck) Evaluate(result *revocation.CheckResult, err error, subject string) rpcert.RevocationDecision {
	return r.mode().Evaluate(revocationState(result, err), subject)
}

// revocationState maps vc's check outcome onto go-trust's state.
//
// Anything that is not plainly valid or plainly revoked - suspended, an
// error, a nil result - becomes Undetermined. Suspended in particular is not
// folded into valid: it means the authority has said something about this
// certificate, just not that it is good.
func revocationState(result *revocation.CheckResult, err error) rpcert.RevocationState {
	if err != nil || result == nil {
		return rpcert.RevocationUndetermined
	}
	switch result.Status {
	case revocation.StatusValid:
		return rpcert.RevocationGood
	case revocation.StatusInvalid, revocation.StatusSuspended:
		return rpcert.RevocationRevoked
	default:
		return rpcert.RevocationUndetermined
	}
}
