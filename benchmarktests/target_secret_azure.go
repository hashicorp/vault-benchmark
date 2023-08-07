// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	AzureSecretTestType       = "azure_secret"
	AzureSecretTestMethod     = "GET"
	AzureSecretSubscriptionID = VaultBenchmarkEnvVarPrefix + "SUBSCRIPTION_ID"
	AzureSecretTenantID       = VaultBenchmarkEnvVarPrefix + "TENANT_ID"
	AzureSecretClientID       = VaultBenchmarkEnvVarPrefix + "CLIENT_ID"
	AzureSecretClientSecret   = VaultBenchmarkEnvVarPrefix + "CLIENT_SECRET"
	AzureSecretEnvironment    = VaultBenchmarkEnvVarPrefix + "ENVIRONMENT"
)

func init() {
	// "Register" this test to the main test registry
	TestList[AzureSecretTestType] = func() BenchmarkBuilder { return &AzureTest{} }
}

type AzureTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *AzureSecretTestConfig
	logger     hclog.Logger
}

type AzureSecretTestConfig struct {
	AzureConfig *AzureSecretConfig `hcl:"azure,block"`
	AzureRole   *AzureSecretRole   `hcl:"role,block"`
}

type AzureSecretConfig struct {
	SubscriptionId  string `hcl:"subscription_id,optional"`
	TenantId        string `hcl:"tenant_id,optional"`
	ClientId        string `hcl:"client_id,optional"`
	ClientSecret    string `hcl:"client_secret,optional"`
	Environment     string `hcl:"environment,optional"`
	PasswordPolicy  string `hcl:"password_policy,optional"`
	RootPasswordTTL string `hcl:"root_password_ttl,optional"`
}

type AzureSecretRole struct {
	Name                string `hcl:"name,optional"`
	AzureRoles          string `hcl:"azure_roles,optional"`
	AzureGroups         string `hcl:"azure_groups,optional"`
	ApplicationObjectId string `hcl:"application_object_id,optional"`
	PersistApp          bool   `hcl:"persist_app,optional"`
	TTL                 string `hcl:"ttl,optional"`
	MaxTTL              string `hcl:"max_ttl,optional"`
	PermanentlyDelete   bool   `hcl:"permanently_delete,optional"`
}

func (a *AzureTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *AzureSecretTestConfig `hcl:"config,block"`
	}{
		Config: &AzureSecretTestConfig{
			AzureConfig: &AzureSecretConfig{
				SubscriptionId: os.Getenv(AzureSecretSubscriptionID),
				TenantId:       os.Getenv(AzureSecretTenantID),
				ClientId:       os.Getenv(AzureSecretClientID),
				ClientSecret:   os.Getenv(AzureSecretClientSecret),
				Environment:    os.Getenv(AzureSecretEnvironment),
			},
			AzureRole: &AzureSecretRole{Name: "benchmark-role"},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	a.config = testConfig.Config

	if a.config.AzureConfig.SubscriptionId == "" {
		return fmt.Errorf("subscription ID is required")
	}

	if a.config.AzureConfig.TenantId == "" {
		return fmt.Errorf("tenant ID is required")
	}

	return nil
}

func (a *AzureTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + a.pathPrefix + "/creds/" + a.roleName,
		Header: a.header,
	}
}

func (a *AzureTest) Cleanup(client *api.Client) error {
	a.logger.Trace(cleanupLogMessage(a.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(a.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (a *AzureTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     AzureSecretTestMethod,
		pathPrefix: a.pathPrefix,
	}
}

func (a *AzureTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	a.logger = targetLogger.Named(AzureSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	config := a.config
	a.logger.Trace(mountLogMessage("secrets", "azure", secretPath))
	setupLogger := a.logger.Named(secretPath)

	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "azure",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting azure: %v", err)
	}

	// Decode Azure Config
	setupLogger.Trace(parsingConfigLogMessage("azure"))
	azureConfigData, err := structToMap(config.AzureConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing azure config from struct: %v", err)
	}

	// Write Azure config
	setupLogger.Trace(writingLogMessage("azure config"))
	_, err = client.Logical().Write(secretPath+"/config", azureConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing azure config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	azureRoleConfigData, err := structToMap(config.AzureRole)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("azure role"), "name", config.AzureRole.Name)
	_, err = client.Logical().Write(secretPath+"/roles/"+config.AzureRole.Name, azureRoleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing azure role: %v", err)
	}

	return &AzureTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.AzureRole.Name,
		logger:     a.logger,
	}, nil
}

func (a *AzureTest) Flags(fs *flag.FlagSet) {}
