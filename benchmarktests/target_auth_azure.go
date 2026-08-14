// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	AzureAuthTestType     = "azure_auth"
	AzureAuthTestMethod   = "POST"
	AzureAuthClientID     = VaultBenchmarkEnvVarPrefix + "AZURE_CLIENT_ID"
	AzureAuthClientSecret = VaultBenchmarkEnvVarPrefix + "AZURE_CLIENT_SECRET"
	AzureAuthJWT          = VaultBenchmarkEnvVarPrefix + "AZURE_JWT"
)

func init() {
	TestList[AzureAuthTestType] = func() BenchmarkBuilder { return &AzureAuth{} }
}

type AzureAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	config     *AzureAuthConfig
	logger     hclog.Logger
}

type AzureAuthConfig struct {
	AzureAuthMountConfig *AzureAuthMountConfig `hcl:"config,block"`
	AzureAuthRoleConfig   *AzureAuthRoleConfig   `hcl:"role,block"`
	AzureAuthUserConfig   *AzureAuthUserConfig   `hcl:"user,block"`
}

type AzureAuthMountConfig struct {
	TenantID     string `hcl:"tenant_id"`
	Resource     string `hcl:"resource"`
	Environment  string `hcl:"environment,optional"`
	ClientID     string `hcl:"client_id,optional"`
	ClientSecret string `hcl:"client_secret,optional"`
}

type AzureAuthRoleConfig struct {
	Name                     string   `hcl:"name,optional"`
	BoundServicePrincipalIDs []string `hcl:"bound_service_principal_ids,optional"`
	BoundGroupIDs            []string `hcl:"bound_group_ids,optional"`
	BoundLocations           []string `hcl:"bound_locations,optional"`
	BoundSubscriptionIDs     []string `hcl:"bound_subscription_ids,optional"`
	BoundResourceGroups      []string `hcl:"bound_resource_groups,optional"`
	BoundScaleSets           []string `hcl:"bound_scale_sets,optional"`
	TokenTTL                 string   `hcl:"token_ttl,optional"`
	TokenMaxTTL              string   `hcl:"token_max_ttl,optional"`
	TokenPolicies            []string `hcl:"token_policies,optional"`
	Policies                 []string `hcl:"policies,optional"`
	TokenBoundCidrs          []string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL      string   `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy     bool     `hcl:"token_no_default_policy,optional"`
	TokenNumUses             int      `hcl:"token_num_uses,optional"`
	TokenPeriod              string   `hcl:"token_period,optional"`
	TokenType                string   `hcl:"token_type,optional"`
}

type AzureAuthUserConfig struct {
	Role              string `hcl:"role,optional"`
	JWT               string `hcl:"jwt,optional"`
	SubscriptionID    string `hcl:"subscription_id"`
	ResourceGroupName string `hcl:"resource_group_name"`
	VMName            string `hcl:"vm_name,optional"`
	VMSSName          string `hcl:"vmss_name,optional"`
	ResourceID        string `hcl:"resource_id,optional"`
}

func (a *AzureAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *AzureAuthConfig `hcl:"config,block"`
	}{
		Config: &AzureAuthConfig{
			AzureAuthMountConfig: &AzureAuthMountConfig{
				ClientID:     os.Getenv(AzureAuthClientID),
				ClientSecret: os.Getenv(AzureAuthClientSecret),
			},
			AzureAuthRoleConfig: &AzureAuthRoleConfig{Name: "benchmark-role"},
			AzureAuthUserConfig: &AzureAuthUserConfig{Role: "benchmark-role",
				JWT: os.Getenv(AzureAuthJWT)},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	a.config = testConfig.Config

	if a.config.AzureAuthUserConfig.JWT == "" {
		return fmt.Errorf("azure JWT required")
	}

	return nil
}

func (a *AzureAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	a.logger = targetLogger.Named(AzureAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	a.logger.Trace(mountLogMessage("auth", "azure", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "azure",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling azure: %v", err)
	}

	setupLogger := a.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("azure auth"))
	if err := writeStruct(client, "auth/"+authPath+"/config", a.config.AzureAuthMountConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("azure auth user"))
	if err := writeStruct(client, "auth/"+authPath+"/role/"+a.config.AzureAuthRoleConfig.Name, a.config.AzureAuthRoleConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("azure auth user"))
	azureAuthUser, err := structToMap(a.config.AzureAuthUserConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding azure auth user from struct: %v", err)
	}

	azureBody, err := json.Marshal(azureAuthUser)
	if err != nil {
		return nil, fmt.Errorf("error marshaling azure login body: %w", err)
	}

	// TODO: Azure JWT expires ~1h; long benchmarks accumulate 401s. Apply cachedBody refresh (see target_auth_aws.go).
	return &AzureAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		body:       azureBody,
		logger:     a.logger,
	}, nil
}

func (a *AzureAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: AzureAuthTestMethod,
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   a.body,
	}
}

func (a *AzureAuth) Cleanup(client *api.Client) error {
	return cleanupMount(a.logger, client, a.pathPrefix)
}

func (a *AzureAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     AzureAuthTestMethod,
		pathPrefix: a.pathPrefix,
	}
}

func (a *AzureAuth) Flags(fs *flag.FlagSet) {}
