// Package docs holds the generated OpenAPI document for the apigw.
package docs

import _ "embed"

// Spec is swagger.json as written by `make swagger-apigw`.
//
//go:embed swagger.json
var Spec []byte
