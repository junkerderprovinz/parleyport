package signin

import _ "embed"

// OpenAPI is the contract Handler serves, for an app that shows it or a
// test that checks answers against it.
//
//go:embed openapi.yaml
var OpenAPI []byte
