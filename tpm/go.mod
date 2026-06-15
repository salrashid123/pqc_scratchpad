module main

go 1.26.2

require (
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.9
)

require (
	filippo.io/mldsa v0.0.0-20260215214346-43d0283efc3e // indirect
	golang.org/x/sys v0.38.0 // indirect
)

replace github.com/google/go-tpm => ./go-tpm
