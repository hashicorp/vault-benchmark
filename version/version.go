// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	// Example embed version usage: this reads contents from version/VERSION at build time and writes the contents to
	// Version and VersionPrerelease

	//go:embed VERSION
	fullVersion string

	Version, VersionPrerelease, _ = strings.Cut(fullVersion, "-")
	VersionMetadata               = ""
)

// GetHumanVersion composes the parts of the version in a way that's suitable
// for displaying to humans.
func GetHumanVersion() string {
	version := fmt.Sprintf("vault-benchmark v%s", Version)
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
