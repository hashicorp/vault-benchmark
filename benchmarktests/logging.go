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

// Translates "/v1/auth/..." to "/sys/auth/..." for the Vault sys delete endpoint.
func cleanupAuthMount(logger hclog.Logger, client *api.Client, pathPrefix string) error {
	logger.Trace(cleanupLogMessage(pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

// Translates "/v1/<mount>" to "/sys/mounts/<mount>" for the Vault sys delete endpoint.
func cleanupSecretMount(logger hclog.Logger, client *api.Client, pathPrefix string) error {
	logger.Trace(cleanupLogMessage(pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}
