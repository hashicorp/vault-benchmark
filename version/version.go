package version

import (
	_ "embed"
	"fmt"
	"strings"
)

var (
	// GitCommit The git commit that was compiled. These will be filled in by the
	// compiler.
	GitCommit string

	// Version is the base version of the product repo
	Version = "1.0.0"
	// VersionPrerelease is the prerelease version of the product repo
	VersionPrerelease = "dev"
	// VersionMetadata is the metadata version of the product repo
	VersionMetadata = ""

	// Version is the base version of the product repo
	// Example embed version usage: this reads contents from version/VERSION at build time and writes the contents to
	// Version and VersionPrerelease
	//
	////go:embed VERSION
	//fullVersion string
	//
	//Version, VersionPrerelease, _ = strings.Cut(fullVersion, "-")
	//VersionMetadata               = ""
)

// GetHumanVersion composes the parts of the version in a way that's suitable
// for displaying to humans.
func GetHumanVersion() string {
	version := Version
	release := VersionPrerelease
	metadata := VersionMetadata

	if release != "" {
		version += fmt.Sprintf("-%s", release)
	}

	if metadata != "" {
		version += fmt.Sprintf("+%s", metadata)
	}

	// Strip off any single quotes added by the git information.
	return strings.ReplaceAll(version, "'", "")
}
