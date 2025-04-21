module test

go 1.23

toolchain go1.23.4

// The version doesn't matter here, as we're replacing it with the currently checked out code anyway.
require github.com/quic-go/quic-go v0.21.0

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/metacubex/utls v1.7.0-alpha.1 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/mod v0.20.0 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	golang.org/x/tools v0.24.0 // indirect
)

replace github.com/quic-go/quic-go => ../../
