// Package webvendor holds third-party browser assets shared by more than one
// service, vendored from npm and served alongside each service's own
// staticembed files.
//
// It exists so a library used by both apigw and verifier is checked in once.
// Two copies drift - the verifier's used to carry an AbortSignal patch that
// upstream lacked - and a duplicated bundle is also counted as duplicated
// source by static analysis.
package webvendor

import "embed"

// FS holds the vendored bundles. Served at /static by every service that
// mounts it, so a page references them the same way whichever service
// delivered the page.
//
//go:embed *.js
var FS embed.FS
