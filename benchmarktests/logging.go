// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import "fmt"

// mountLogMessage returns a common formatted log message to be emitted
// when creating a new Auth method or Secret Engine mount
func mountLogMessage(mountType string, methodOrEngineType string, path string) string {
	switch mountType {
	case "auth":
		return fmt.Sprintf("mounting %v auth method at: path=%v", methodOrEngineType, path)

	case "secrets":
		return fmt.Sprintf("mounting %v secrets engine at: path=%v", methodOrEngineType, path)

	default:
		return fmt.Sprintf("creating mount: kind=%v type=%v path=%v", mountType, methodOrEngineType, path)
	}
}

// cleanupLogMessage provides a common formatted log message to be
// emitted when running a cleanup for a benchmark test
func cleanupLogMessage(pathPrefix string) string {
	return fmt.Sprintf("unmounting: path=%v", pathPrefix)
}

// parsingConfigLogMessage provides a common formatted log message to
// be emitted when parsing configuration from a struct to a map for use
// in an API request
func parsingConfigLogMessage(configType string) string {
	return fmt.Sprintf("parsing %v config data", configType)
}

// writingLogMessage provides a common formatted log message to be
// emitted when issuing a logical write API call to a specific kind
// of resource
func writingLogMessage(kind string) string {
	return fmt.Sprintf("writing %v", kind)
}
