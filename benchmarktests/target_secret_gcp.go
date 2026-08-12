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
	GCPSecretTestType     = "gcp_secret"
	GCPSecretTestMethod   = "GET"
	GCPSecretCredentials  = VaultBenchmarkEnvVarPrefix + "GCP_CREDENTIALS"
	GCPSecretBindings     = VaultBenchmarkEnvVarPrefix + "GCP_BINDINGS"
	GCPAccessTokenType    = "access_token"
	GCPServiceAccountType = "service_account_key"
)

func init() {
	TestList[GCPSecretTestType] = func() BenchmarkBuilder { return &GCPSecret{} }
}

type GCPSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	targetURL  string
	config     *GCPSecretConfig
	logger     hclog.Logger
}

type GCPSecretConfig struct {
	GCPConfig  *GCPSecretMountConfig  `hcl:"gcp,block"`
	GCPRoleset *GCPSecretRoleset `hcl:"roleset,block"`
}

type GCPSecretMountConfig struct {
	Credentials string `hcl:"credentials,optional"`
	TTL         string `hcl:"ttl,optional"`
	MaxTTL      string `hcl:"max_ttl,optional"`
}

type GCPSecretRoleset struct {
	Name        string   `hcl:"name,optional"`
	SecretType  string   `hcl:"secret_type,optional"`
	Project     string   `hcl:"project"`
	Bindings    string   `hcl:"bindings,optional"`
	TokenScopes []string `hcl:"token_scopes,optional"`
}

func (g *GCPSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *GCPSecretConfig `hcl:"config,block"`
	}{
		Config: &GCPSecretConfig{
			GCPConfig:  &GCPSecretMountConfig{Credentials: os.Getenv(GCPSecretCredentials)},
			GCPRoleset: &GCPSecretRoleset{Name: "benchmark-roleset", SecretType: GCPAccessTokenType, Bindings: os.Getenv(GCPSecretBindings)},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	g.config = testConfig.Config

	if g.config.GCPRoleset.Project == "" {
		return fmt.Errorf("GCP project is required")
	}

	if g.config.GCPRoleset.Bindings == "" {
		return fmt.Errorf("GCP bindings are required")
	}

	if g.config.GCPConfig.Credentials == "" {
		return fmt.Errorf("GCP Credentials are required")
	}

	return nil
}

func (g *GCPSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	g.logger = targetLogger.Named(RedisDynamicSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	config := g.config
	g.logger.Trace(mountLogMessage("secrets", "gcp", secretPath))
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

	// check if the bindings argument should be read from file
	bindings := config.GCPRoleset.Bindings
	if len(bindings) > 0 && bindings[0] == '@' {
		contents, err := os.ReadFile(bindings[1:])
		if err != nil {
			return nil, fmt.Errorf("error reading bindings file: %w", err)
		}

		config.GCPRoleset.Bindings = string(contents)
	}

	setupLogger.Trace(parsingConfigLogMessage("gcp"))
	if err := writeStruct(client, secretPath+"/config", config.GCPConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, secretPath+"/roleset/"+config.GCPRoleset.Name, config.GCPRoleset); err != nil {
		return nil, err
	}

	suffix := "/token"
	if config.GCPRoleset.SecretType == GCPServiceAccountType {
		suffix = "/key"
	}
	return &GCPSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.GCPRoleset.Name,
		targetURL:  client.Address() + "/v1/" + secretPath + "/roleset/" + config.GCPRoleset.Name + suffix,
		logger:     g.logger,
	}, nil
}

func (g *GCPSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: GCPSecretTestMethod,
		URL:    g.targetURL,
		Header: g.header,
	}
}

func (g *GCPSecret) Cleanup(client *api.Client) error {
	return cleanupMount(g.logger, client, g.pathPrefix)
}

func (g *GCPSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GCPSecretTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (g *GCPSecret) Flags(fs *flag.FlagSet) {}
