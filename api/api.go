// Package api holds the OpenAPI description of the HTTP layer of the
// protocol: its routes, members, statuses and headers, in openapi.yaml.
// PROTOCOL.md is the specification, and governs where the two differ. Nothing
// in the description protects a message: every check a client makes is in
// PROTOCOL.md. Package apitest holds a server's answers to it, in tests.
package api

import _ "embed" // the description

// OpenAPI is openapi.yaml, the description.
//
//go:embed openapi.yaml
var OpenAPI []byte
