module test

go 1.24

// The version doesn't matter here, as we're replacing it with the currently checked out code anyway.
require github.com/quic-go/quic-go v0.21.0

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/metacubex/utls v1.8.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
)

replace github.com/quic-go/quic-go => ../../
