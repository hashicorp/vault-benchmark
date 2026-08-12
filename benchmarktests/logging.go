// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
)

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

func cleanupLogMessage(pathPrefix string) string {
	return fmt.Sprintf("unmounting: path=%v", pathPrefix)
}

func parsingConfigLogMessage(configType string) string {
	return fmt.Sprintf("parsing %v config data", configType)
}

func writingLogMessage(kind string) string {
	return fmt.Sprintf("writing %v", kind)
}

// cleanupMount deletes the Vault mount backing pathPrefix.
// Auth mounts ("/v1/auth/<name>") map to "/sys/auth/<name>";
// all other mounts ("/v1/<name>") map to "/sys/mounts/<name>".
func cleanupMount(logger hclog.Logger, client *api.Client, pathPrefix string) error {
	logger.Trace(cleanupLogMessage(pathPrefix))
	var sysPath string
	if strings.HasPrefix(pathPrefix, "/v1/auth/") {
		sysPath = strings.Replace(pathPrefix, "/v1/", "/sys/", 1)
	} else {
		sysPath = strings.Replace(pathPrefix, "/v1/", "/sys/mounts/", 1)
	}
	if _, err := client.Logical().Delete(sysPath); err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}
