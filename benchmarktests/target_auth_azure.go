// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
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
	AzureAuthTestType               = "azure_auth"
	AzureAuthTestMethod             = "POST"
	AzureAuthTestUserClientIDEnvVar = VaultBenchmarkEnvVarPrefix + "AZURE_TEST_CLIENT_ID"
	AzureAuthTestUserPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "AZURE_TEST_SECRET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[AzureAuthTestType] = func() BenchmarkBuilder { return &AzureAuth{} }
}

type AzureAuth struct {
	pathPrefix string
	role       string
	jwt        string
	header     http.Header
	config     *AzureAuthTestConfig
	logger     hclog.Logger
}

type AzureAuthTestConfig struct {
	AzureAuthConfig     *AzureAuthConfig     `hcl:"auth,block"`
	AzureTestUserConfig *AzureTestUserConfig `hcl:"test_user,block"`
}

type AzureAuthConfig struct {
	TenantId     string `hcl:"tenant_id"`
	Resource     string `hcl:"resource"`
	Environment  string `hcl:"environment,optional"`
	ClientId     string `hcl:"client_id,optional"`
	ClientSecret string `hcl:"client_secret,optional"`
}

type AzureTestUserConfig struct {
	Role              string `hcl:"role"`
	JWT               string `hcl:"jwt"`
	SubscriptionId    string `hcl:"subscription_id"`
	ResourceGroupName string `hcl:"resource_group_name"`
	VMName            string `hcl:"vm_name,optional"`
	VMSSName          string `hcl:"vmss_name,optional"`
	ResourceId        string `hcl:"resource_id,optional"`
}

func (a *AzureAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *AzureAuthTestConfig `hcl:"config,block"`
	}{
		Config: &AzureAuthTestConfig{
			AzureAuthConfig: &AzureAuthConfig{
				ClientId:     os.Getenv(AzureAuthTestUserClientIDEnvVar),
				ClientSecret: os.Getenv(AzureAuthTestUserPasswordEnvVar),
			},
			AzureTestUserConfig: &AzureTestUserConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	a.config = testConfig.Config

	// Empty Credentials check
	if a.config.AzureAuthConfig.ClientId == "" {
		return fmt.Errorf("no client_id provided for vault to use")
	}

	if a.config.AzureAuthConfig.ClientSecret == "" {
		return fmt.Errorf("no client_secret provided for vault to use")
	}

	return nil
}

func (a *AzureAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + a.pathPrefix + "/login/",
		Header: a.header,
		Body:   []byte(fmt.Sprintf(`{"role": "%s", "jwt": "%s"}`, a.role, a.jwt)),
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

func (a *AzureAuth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	config := a.config
	a.logger = targetLogger.Named(AzureAuthTestType)

	if randomMountName {
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

	// Decode AzureConfig struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("azure auth"))
	azureAuthConfig, err := structToMap(config.AzureAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding azure auth config from struct: %v", err)
	}

	// Write Azure config
	setupLogger.Trace(writingLogMessage("azure auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config", azureAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing azure auth config: %v", err)
	}

	return &AzureAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		role:       config.AzureTestUserConfig.Role,
		jwt:        config.AzureTestUserConfig.JWT,
		logger:     a.logger,
	}, nil
}

// Func Flags accepts a flag set to assign additional flags defined in the function
func (a *AzureAuth) Flags(fs *flag.FlagSet) {}
