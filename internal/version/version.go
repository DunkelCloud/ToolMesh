// Package version holds build-time version information.
// Values are injected via -ldflags during compilation:
//
//	go build -ldflags "-X github.com/DunkelCloud/ToolMesh/internal/version.Version=1.0.0 ..."
package version

// These variables are set at build time via -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
