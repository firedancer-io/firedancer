module github.com/firedancer-io/firedancer/contrib/quic/go_compat

// Set this to Go 1.23 to enable post-quantum key exchange
go 1.23.0

toolchain go1.23.6

require (
	github.com/quic-go/quic-go v0.54.1
	golang.org/x/net v0.40.0
)

require (
	github.com/francoispqt/gojay v1.2.13 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
)
