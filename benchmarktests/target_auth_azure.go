// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	AzureAuthTestType     = "azure_auth"
	AzureAuthTestMethod   = "POST"
	AzureAuthClientID     = VaultBenchmarkEnvVarPrefix + "AZURE_CLIENT_ID"
	AzureAuthClientSecret = VaultBenchmarkEnvVarPrefix + "AZURE_CLIENT_SECRET"
	AzureAuthJWT          = VaultBenchmarkEnvVarPrefix + "AZURE_JWT"
)

func init() {
	// "Register" this test to the main test registry
	TestList[AzureAuthTestType] = func() BenchmarkBuilder { return &AzureAuth{} }
}

type AzureAuth struct {
	pathPrefix string
	loginData  map[string]interface{}
	header     http.Header
	config     *AzureAuthTestConfig
	logger     hclog.Logger
}

type AzureAuthTestConfig struct {
	AzureAuthConfig *AzureAuthConfig `hcl:"config,block"`
	AzureAuthRole   *AzureAuthRole   `hcl:"role,block"`
	AzureAuthUser   *AzureAuthUser   `hcl:"user,block"`
}

type AzureAuthConfig struct {
	TenantID     string `hcl:"tenant_id"`
	Resource     string `hcl:"resource"`
	Environment  string `hcl:"environment,optional"`
	ClientID     string `hcl:"client_id,optional"`
	ClientSecret string `hcl:"client_secret,optional"`
}

type AzureAuthRole struct {
	Name                     string   `hcl:"string,optional"`
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

type AzureAuthUser struct {
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
		Config *AzureAuthTestConfig `hcl:"config,block"`
	}{
		Config: &AzureAuthTestConfig{
			AzureAuthConfig: &AzureAuthConfig{
				ClientID:     os.Getenv(AzureAuthClientID),
				ClientSecret: os.Getenv(AzureAuthClientSecret),
			},
			AzureAuthRole: &AzureAuthRole{Name: "benchmark-role"},
			AzureAuthUser: &AzureAuthUser{Role: "benchmark-role",
				JWT: os.Getenv(AzureAuthJWT)},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	a.config = testConfig.Config

	// Empty Credentials check
	if a.config.AzureAuthUser.JWT == "" {
		return fmt.Errorf("azure JWT required")
	}

	return nil
}

func (a *AzureAuth) Target(client *api.Client) vegeta.Target {
	jsonData, _ := json.Marshal(a.loginData)
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   jsonData,
	}
}

func (a *AzureAuth) Cleanup(client *api.Client) error {
	a.logger.Trace(cleanupLogMessage(a.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(a.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (a *AzureAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     AzureAuthTestMethod,
		pathPrefix: a.pathPrefix,
	}
}

func (a *AzureAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	a.logger = targetLogger.Named(AzureAuthTestType)

	if topLevelConfig.RandomMounts {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Azure Auth mount
	a.logger.Trace(mountLogMessage("auth", "azure", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "azure",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling azure: %v", err)
	}

	setupLogger := a.logger.Named(authPath)

	// Decode AzureAuthConfig struct into mapstructure to pass with request

	setupLogger.Trace(parsingConfigLogMessage("azure auth"))
	azureAuthConfig, err := structToMap(a.config.AzureAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding azure auth config from struct: %v", err)
	}

	// Write Azure config
	setupLogger.Trace(writingLogMessage("azure auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config", azureAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing azure auth config: %v", err)
	}

	// Decode AzureAuthRole struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("azure auth user"))
	azureAuthRole, err := structToMap(a.config.AzureAuthRole)
	if err != nil {
		return nil, fmt.Errorf("error decoding azure auth role from struct: %v", err)
	}

	// Create Azure Test Role
	setupLogger.Trace(writingLogMessage("azure auth user config"))
	_, err = client.Logical().Write("auth/"+authPath+"/role/"+a.config.AzureAuthRole.Name, azureAuthRole)
	if err != nil {
		return nil, fmt.Errorf("error writing azure auth user: %v", err)
	}

	// Decode AzureAuthUser struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("azure auth user"))
	azureAuthUser, err := structToMap(a.config.AzureAuthUser)
	if err != nil {
		return nil, fmt.Errorf("error decoding azure auth user from struct: %v", err)
	}

	return &AzureAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		logger:     a.logger,
		config:     a.config,
		loginData:  azureAuthUser,
	}, nil
}

// Func Flags accepts a flag set to assign additional flags defined in the function
func (a *AzureAuth) Flags(fs *flag.FlagSet) {}
