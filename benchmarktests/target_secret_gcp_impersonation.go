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
	GCPImpersonationSecretTestType            = "gcp_impersonation_secret"
	GCPImpersonationSecretTestMethod          = "GET"
	GCPImpersonationSecretServiceAccountEmail = VaultBenchmarkEnvVarPrefix + "GCP_SERVICE_ACCOUNT_EMAIL"
)

func init() {
	TestList[GCPImpersonationSecretTestType] = func() BenchmarkBuilder { return &GCPImpersonationSecret{} }
}

type GCPImpersonationSecret struct {
	pathPrefix string
	header     http.Header
	config     *GCPImpersonationSecretConfig
	logger     hclog.Logger
}

type GCPImpersonationSecretConfig struct {
	GCPConfig      *GCPSecretMountConfig `hcl:"gcp,block"`
	GCPImpersonate *GCPImpersonate  `hcl:"impersonate,block"`
}

type GCPImpersonate struct {
	Name                string   `hcl:"name,optional"`
	ServiceAccountEmail string   `hcl:"service_account_email,optional"`
	TTL                 string   `hcl:"ttl,optional"`
	TokenScopes         []string `hcl:"token_scopes,optional"`
}

func (g *GCPImpersonationSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *GCPImpersonationSecretConfig `hcl:"config,block"`
	}{
		Config: &GCPImpersonationSecretConfig{
			GCPConfig:      &GCPSecretMountConfig{Credentials: os.Getenv(GCPSecretCredentials)},
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

func (g *GCPImpersonationSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	g.logger = targetLogger.Named(GCPImpersonationSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
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
		contents, err := os.ReadFile(creds[1:])
		if err != nil {
			return nil, fmt.Errorf("error reading credentials file: %w", err)
		}

		config.GCPConfig.Credentials = string(contents)
	}

	setupLogger.Trace(parsingConfigLogMessage("gcp impersonation"))
	if err := writeStruct(client, secretPath+"/config", config.GCPConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("gcp impersonation"))
	if err := writeStruct(client, secretPath+"/impersonated-account/"+config.GCPImpersonate.Name, config.GCPImpersonate); err != nil {
		return nil, err
	}

	return &GCPImpersonationSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		logger:     g.logger,
		config:     g.config,
	}, nil
}

func (g *GCPImpersonationSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: GCPImpersonationSecretTestMethod,
		URL:    client.Address() + g.pathPrefix + "/impersonated-account/" + g.config.GCPImpersonate.Name,
		Header: g.header,
	}
}

func (g *GCPImpersonationSecret) Cleanup(client *api.Client) error {
	return cleanupMount(g.logger, client, g.pathPrefix)
}

func (g *GCPImpersonationSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GCPImpersonationSecretTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (a *GCPImpersonationSecret) Flags(fs *flag.FlagSet) {}
