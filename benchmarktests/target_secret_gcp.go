// Copyright (c) HashiCorp, Inc.
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
	GCPSecretTestType     = "gcp_secret"
	GCPSecretTestMethod   = "GET"
	GCPSecretCredentials  = VaultBenchmarkEnvVarPrefix + "GCP_CREDENTIALS"
	GCPSecretBindings     = VaultBenchmarkEnvVarPrefix + "GCP_BINDINGS"
	GCPAccessTokenType    = "access_token"
	GCPServiceAccountType = "service_account_key"
)

func init() {
	// "Register" this test to the main test registry
	TestList[GCPSecretTestType] = func() BenchmarkBuilder { return &GCPTest{} }
}

type GCPTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *GCPSecretTestConfig
	logger     hclog.Logger
}

type GCPSecretTestConfig struct {
	GCPConfig  *GCPSecretConfig  `hcl:"gcp,block"`
	GCPRoleset *GCPSecretRoleset `hcl:"roleset,block"`
}

type GCPSecretConfig struct {
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

func (g *GCPTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *GCPSecretTestConfig `hcl:"config,block"`
	}{
		Config: &GCPSecretTestConfig{
			GCPConfig:  &GCPSecretConfig{Credentials: os.Getenv(GCPSecretCredentials)},
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

func (g *GCPTest) Target(client *api.Client) vegeta.Target {
	var url string

	if g.config.GCPRoleset.SecretType == GCPAccessTokenType {
		url = client.Address() + g.pathPrefix + "/roleset/" + g.roleName + "/token"
	} else if g.config.GCPRoleset.SecretType == GCPServiceAccountType {
		url = client.Address() + g.pathPrefix + "/roleset/" + g.roleName + "/key"
	}

	return vegeta.Target{
		Method: "GET",
		URL:    url,
		Header: g.header,
	}
}

func (g *GCPTest) Cleanup(client *api.Client) error {
	g.logger.Trace(cleanupLogMessage(g.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(g.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (g *GCPTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GCPSecretTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (g *GCPTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	g.logger = targetLogger.Named(GCPSecretTestType)

	secretPath := mountName
	if randomMountName {
		var err error
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	config := g.config
	g.logger.Trace(mountLogMessage("secrets", "gcp", secretPath))
	setupLogger := g.logger.Named(secretPath)

	err := client.Sys().Mount(secretPath, &api.MountInput{
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

	// check if the bindings argument should be read from file
	bindings := config.GCPRoleset.Bindings
	if len(bindings) > 0 && bindings[0] == '@' {
		contents, err := ioutil.ReadFile(bindings[1:])
		if err != nil {
			return nil, fmt.Errorf("error reading bindings file: %w", err)
		}

		config.GCPRoleset.Bindings = string(contents)
	}

	// Encode GCP Config
	setupLogger.Trace(parsingConfigLogMessage("gcp"))
	gcpConfigData, err := structToMap(config.GCPConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing gcp config from struct: %v", err)
	}

	// Write GCP config
	setupLogger.Trace(writingLogMessage("gcp config"))
	_, err = client.Logical().Write(secretPath+"/config", gcpConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing gcp config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	gcpRolesetData, err := structToMap(config.GCPRoleset)
	if err != nil {
		return nil, fmt.Errorf("error parsing roleset config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("gcp roleset"), "name", config.GCPRoleset.Name)
	_, err = client.Logical().Write(secretPath+"/roleset/"+config.GCPRoleset.Name, gcpRolesetData)
	if err != nil {
		return nil, fmt.Errorf("error writing gcp roleset: %v", err)
	}

	return &GCPTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.GCPRoleset.Name,
		logger:     g.logger,
		config:     g.config,
	}, nil
}

func (g *GCPTest) Flags(fs *flag.FlagSet) {}
