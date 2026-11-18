// Package version carries the dex build version. The value is overridden at
// build time:
//
//	go build -ldflags "-X github.com/dexidp/dex/version.Version=v2.4.0" ./cmd/dex
//
// Without it a build reports "DEV", which is what a bare `go build` produces.
package version

// Version is the version of this build.
var Version = "DEV"
