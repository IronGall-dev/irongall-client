module github.com/IronGall-dev/irongall-client

go 1.27.0

require (
	filippo.io/age v1.3.2
	filippo.io/edwards25519 v1.2.0
	github.com/pb33f/libopenapi v0.41.6
	github.com/pb33f/libopenapi-validator v0.16.1
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
	golang.org/x/crypto v0.58.0
)

require (
	filippo.io/hpke v0.4.0 // indirect
	filippo.io/nistec v0.0.4 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/basgys/goxml2json v1.1.1-0.20231018121955-e66ee54ceaad // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/go-openapi/jsonpointer v1.0.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pb33f/go-yaml v0.1.1 // indirect
	github.com/pb33f/jsonpath v0.8.4 // indirect
	github.com/pb33f/jsonschema/v6 v6.0.3 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.2 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

tool (
	filippo.io/age/cmd/age
	filippo.io/age/cmd/age-keygen
)
