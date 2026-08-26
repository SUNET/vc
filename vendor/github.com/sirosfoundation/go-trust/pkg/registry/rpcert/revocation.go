// Revocation references and the decision that acts on them.
//
// Three unrelated things are called "revocation" in this ecosystem, and
// conflating them is the easiest way to build the wrong one:
//
//   - An access certificate (WRPAC) is revoked through an X.509 CRL or OCSP.
//   - A registration certificate (WRPRC) is revoked through the IETF Token
//     Status List referenced by its own status claim.
//   - An issued credential is revoked through its own status list, which has
//     nothing to do with either of the above.
//
// This file covers the first two. It surfaces where to look and decides what
// an answer means; it does not fetch anything. go-trust performs no I/O, so
// the caller supplies a checker - the same shape as the injected key
// resolvers used elsewhere in this repository.

package rpcert

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
)

// RevocationState is what a checker found out about a certificate.
//
// Undetermined is a distinct outcome rather than a flavour of Good on
// purpose. An unreachable CRL is not evidence that a certificate is valid,
// and collapsing the two is precisely how a fetch failure quietly becomes a
// pass.
type RevocationState string

const (
	// RevocationGood means the responder was reached and did not list the
	// certificate as revoked.
	RevocationGood RevocationState = "good"

	// RevocationRevoked means the responder listed the certificate as
	// revoked.
	RevocationRevoked RevocationState = "revoked"

	// RevocationUndetermined means no answer was obtained - the list was
	// unreachable, malformed, untrusted, or the certificate carried no
	// revocation reference at all.
	RevocationUndetermined RevocationState = "undetermined"
)

// RevocationMode is how a deployment wants an outcome treated.
type RevocationMode string

const (
	// RevocationOff performs no check. Every state is allowed.
	RevocationOff RevocationMode = "off"

	// RevocationWarn allows every state but reports a reason for anything
	// other than Good. This is the appropriate default: a Registrar outage
	// should not become our outage.
	RevocationWarn RevocationMode = "warn"

	// RevocationFail rejects both Revoked and Undetermined. Undetermined is
	// rejected because a deployment choosing this mode has said it would
	// rather stop than proceed without an answer.
	RevocationFail RevocationMode = "fail"
)

// Valid reports whether m is a recognised mode.
func (m RevocationMode) Valid() bool {
	switch m {
	case RevocationOff, RevocationWarn, RevocationFail:
		return true
	}
	return false
}

// RevocationDecision is the outcome of applying a mode to a state.
//
// Allowed and Reason are separate because "allowed, but you should know
// about this" is a real and common outcome under RevocationWarn. A caller
// that only reads Allowed silently discards the warning, so Reason is
// populated whenever there is anything to say.
type RevocationDecision struct {
	// State is the state the decision was made about.
	State RevocationState
	// Allowed reports whether the certificate may be used.
	Allowed bool
	// Reason is a human-readable explanation, empty only when the state was
	// Good or the mode was Off.
	Reason string
}

// Evaluate applies the mode to a checker's finding.
//
// An unknown mode is treated as RevocationWarn rather than silently allowing
// everything: a typo in configuration should not disable a check without
// saying so.
func (m RevocationMode) Evaluate(state RevocationState, subject string) RevocationDecision {
	if subject == "" {
		subject = "certificate"
	}
	if m == RevocationOff {
		return RevocationDecision{State: state, Allowed: true}
	}
	strict := m == RevocationFail

	switch state {
	case RevocationGood:
		return RevocationDecision{State: state, Allowed: true}
	case RevocationRevoked:
		return RevocationDecision{
			State:   state,
			Allowed: !strict,
			Reason:  fmt.Sprintf("%s has been revoked", subject),
		}
	default:
		return RevocationDecision{
			State:   RevocationUndetermined,
			Allowed: !strict,
			Reason: fmt.Sprintf("could not determine whether %s has been revoked; "+
				"this is not evidence that it is valid", subject),
		}
	}
}

// StatusReference locates one entry in an IETF Token Status List - the
// mechanism a WRPRC is revoked through (TS 119 475 Table 7, `status`).
type StatusReference struct {
	// URI is where the status list is published.
	URI string
	// Index is this certificate's position within that list.
	Index int
}

// StatusReference returns the WRPRC's Token Status List entry, and whether
// the certificate carried one.
//
// A WRPRC without a status reference is not revocable at all, which callers
// should treat as Undetermined rather than Good - see RevocationMode.
func (e *RPEntitlements) StatusReference() (StatusReference, bool) {
	if e == nil || e.StatusListURI == "" {
		return StatusReference{}, false
	}
	return StatusReference{URI: e.StatusListURI, Index: e.StatusListIndex}, true
}

// StatusListChecker resolves a Token Status List entry to a state.
//
// go-trust defines the shape and interprets the answer; the implementation -
// fetching, caching, verifying the status list's own signature - belongs to
// the caller, which is the layer that owns network policy.
type StatusListChecker interface {
	CheckStatus(ctx context.Context, ref StatusReference) (RevocationState, error)
}

// CertRevocationChecker resolves an X.509 certificate to a state, through
// whichever of CRL or OCSP the caller implements.
type CertRevocationChecker interface {
	CheckCertificate(ctx context.Context, cert *x509.Certificate) (RevocationState, error)
}

// CRLDistributionPoints returns the HTTP(S) CRL distribution point URLs from
// a certificate, in order and without duplicates.
//
// Only http and https are returned. A CRL published over ldap or through a
// directoryName general name is not something a caller here can fetch, and
// returning one would produce an Undetermined result that looks like a
// fetch failure rather than an unsupported scheme.
//
// An empty result means the certificate cannot be checked this way, which is
// Undetermined - not Good.
func CRLDistributionPoints(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	seen := make(map[string]bool, len(cert.CRLDistributionPoints))
	var out []string
	for _, dp := range cert.CRLDistributionPoints {
		if seen[dp] {
			continue
		}
		u, err := url.Parse(dp)
		if err != nil {
			continue
		}
		switch u.Scheme {
		case "http", "https":
		default:
			continue
		}
		seen[dp] = true
		out = append(out, dp)
	}
	return out
}

// OCSPResponders returns the OCSP responder URLs from a certificate, in
// order and without duplicates. Same scheme restriction as
// CRLDistributionPoints.
func OCSPResponders(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	seen := make(map[string]bool, len(cert.OCSPServer))
	var out []string
	for _, s := range cert.OCSPServer {
		if seen[s] {
			continue
		}
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		switch u.Scheme {
		case "http", "https":
		default:
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
