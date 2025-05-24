module github.com/firedancer-io/firedancer/contrib/quic/go_compat

// Set this to Go 1.23 to enable post-quantum key exchange
go 1.23.0

toolchain go1.23.6

require (
	github.com/quic-go/quic-go v0.52.0
	golang.org/x/net v0.40.0
)

require (
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
)
