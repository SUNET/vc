// Package docs holds the generated OpenAPI document for the issuer.
package docs

import _ "embed"

// Spec is swagger.json as written by `make swagger-issuer`.
//
//go:embed swagger.json
var Spec []byte
