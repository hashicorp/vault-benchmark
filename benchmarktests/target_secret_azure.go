// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

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
	TestList[AzureSecretTestType] = func() BenchmarkBuilder { return &AzureSecret{} }
}

type AzureSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *AzureSecretConfig
	logger     hclog.Logger
}

type AzureSecretConfig struct {
	AzureConfig *AzureSecretMountConfig `hcl:"azure,block"`
	AzureRole   *AzureSecretRoleConfig   `hcl:"role,block"`
}

type AzureSecretMountConfig struct {
	SubscriptionId  string `hcl:"subscription_id,optional"`
	TenantId        string `hcl:"tenant_id,optional"`
	ClientId        string `hcl:"client_id,optional"`
	ClientSecret    string `hcl:"client_secret,optional"`
	Environment     string `hcl:"environment,optional"`
	PasswordPolicy  string `hcl:"password_policy,optional"`
	RootPasswordTTL string `hcl:"root_password_ttl,optional"`
}

type AzureSecretRoleConfig struct {
	Name                string `hcl:"name,optional"`
	AzureRoles          string `hcl:"azure_roles,optional"`
	AzureGroups         string `hcl:"azure_groups,optional"`
	ApplicationObjectId string `hcl:"application_object_id,optional"`
	PersistApp          bool   `hcl:"persist_app,optional"`
	TTL                 string `hcl:"ttl,optional"`
	MaxTTL              string `hcl:"max_ttl,optional"`
	PermanentlyDelete   bool   `hcl:"permanently_delete,optional"`
}

func (a *AzureSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *AzureSecretConfig `hcl:"config,block"`
	}{
		Config: &AzureSecretConfig{
			AzureConfig: &AzureSecretMountConfig{
				SubscriptionId: os.Getenv(AzureSecretSubscriptionID),
				TenantId:       os.Getenv(AzureSecretTenantID),
				ClientId:       os.Getenv(AzureSecretClientID),
				ClientSecret:   os.Getenv(AzureSecretClientSecret),
				Environment:    os.Getenv(AzureSecretEnvironment),
			},
			AzureRole: &AzureSecretRoleConfig{Name: "benchmark-role"},
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

func (a *AzureSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	a.logger = targetLogger.Named(AzureSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
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

	setupLogger.Trace(parsingConfigLogMessage("azure"))
	if err := writeStruct(client, secretPath+"/config", config.AzureConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, secretPath+"/roles/"+config.AzureRole.Name, config.AzureRole); err != nil {
		return nil, err
	}

	return &AzureSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.AzureRole.Name,
		logger:     a.logger,
	}, nil
}

func (a *AzureSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: AzureSecretTestMethod,
		URL:    client.Address() + a.pathPrefix + "/creds/" + a.roleName,
		Header: a.header,
	}
}

func (a *AzureSecret) Cleanup(client *api.Client) error {
	return cleanupMount(a.logger, client, a.pathPrefix)
}

func (a *AzureSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     AzureSecretTestMethod,
		pathPrefix: a.pathPrefix,
	}
}

func (a *AzureSecret) Flags(fs *flag.FlagSet) {}
