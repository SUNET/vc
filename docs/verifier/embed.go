// Package docs holds the generated OpenAPI document for the verifier.
package docs

import _ "embed"

// Spec is swagger.json as written by `make swagger-verifier`.
//
//go:embed swagger.json
var Spec []byte
