// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"io/ioutil"
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
	GCPImpersonationSecretTestType            = "gcp_impersonation_secret"
	GCPImpersonationSecretTestMethod          = "GET"
	GCPImpersonationSecretServiceAccountEmail = VaultBenchmarkEnvVarPrefix + "GCP_SERVICE_ACCOUNT_EMAIL"
)

func init() {
	// "Register" this test to the main test registry
	TestList[GCPImpersonationSecretTestType] = func() BenchmarkBuilder { return &GCPImpersonationTest{} }
}

type GCPImpersonationTest struct {
	pathPrefix string
	header     http.Header
	config     *GCPImpersonationSecretTestConfig
	logger     hclog.Logger
}

type GCPImpersonationSecretTestConfig struct {
	GCPConfig      *GCPSecretConfig `hcl:"gcp,block"`
	GCPImpersonate *GCPImpersonate  `hcl:"impersonate,block"`
}

type GCPImpersonate struct {
	Name                string   `hcl:"name,optional"`
	ServiceAccountEmail string   `hcl:"service_account_email,optional"`
	TTL                 string   `hcl:"ttl,optional"`
	TokenScopes         []string `hcl:"token_scopes,optional"`
}

func (g *GCPImpersonationTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *GCPImpersonationSecretTestConfig `hcl:"config,block"`
	}{
		Config: &GCPImpersonationSecretTestConfig{
			GCPConfig:      &GCPSecretConfig{Credentials: os.Getenv(GCPSecretCredentials)},
			GCPImpersonate: &GCPImpersonate{Name: "benchmark-gcp-impersonation", ServiceAccountEmail: os.Getenv(GCPImpersonationSecretServiceAccountEmail)},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	g.config = testConfig.Config

	if g.config.GCPImpersonate.ServiceAccountEmail == "" {
		return fmt.Errorf("GCP Service Account Email is required")
	}

	if g.config.GCPConfig.Credentials == "" {
		return fmt.Errorf("GCP Credentials are required")
	}

	return nil
}

func (g *GCPImpersonationTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + g.pathPrefix + "/impersonated-account/" + g.config.GCPImpersonate.Name,
		Header: g.header,
	}
}

func (g *GCPImpersonationTest) Cleanup(client *api.Client) error {
	g.logger.Trace(cleanupLogMessage(g.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(g.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up gcp impersonation mount: %v", err)
	}
	return nil
}

func (g *GCPImpersonationTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GCPImpersonationSecretTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (g *GCPImpersonationTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	g.logger = targetLogger.Named(GCPImpersonationSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	config := g.config
	g.logger.Trace(mountLogMessage("secrets", "gcp_impersonation", secretPath))
	setupLogger := g.logger.Named(secretPath)

	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "gcp",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting gcp: %v", err)
	}

	// check if the credentials argument should be read from file
	creds := config.GCPConfig.Credentials
	if len(creds) > 0 && creds[0] == '@' {
		contents, err := ioutil.ReadFile(creds[1:])
		if err != nil {
			return nil, fmt.Errorf("error reading credentials file: %w", err)
		}

		config.GCPConfig.Credentials = string(contents)
	}

	// Encode GCP Config
	setupLogger.Trace(parsingConfigLogMessage("gcp impersonation"))
	gcpImpersonationConfigData, err := structToMap(config.GCPConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing gcp config from struct: %v", err)
	}

	// Write GCP config
	setupLogger.Trace(writingLogMessage("gcp impersonation config"))
	_, err = client.Logical().Write(secretPath+"/config", gcpImpersonationConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing gcp config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("gcp impersonation"))
	gcpImpersonationData, err := structToMap(config.GCPImpersonate)
	if err != nil {
		return nil, fmt.Errorf("error parsing gcp impersonation config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("gcp impersonation"), "name", config.GCPImpersonate.Name)
	_, err = client.Logical().Write(secretPath+"/impersonated-account/"+config.GCPImpersonate.Name, gcpImpersonationData)
	if err != nil {
		return nil, fmt.Errorf("error writing gcp impersonation: %v", err)
	}

	return &GCPImpersonationTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		logger:     g.logger,
		config:     g.config,
	}, nil
}

func (a *GCPImpersonationTest) Flags(fs *flag.FlagSet) {}
