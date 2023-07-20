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
	NomadSecretTestType   = "nomad_secret"
	NomadSecretTestMethod = "GET"
	NomadTokenEnvVar      = VaultBenchmarkEnvVarPrefix + "NOMAD_TOKEN"
)

func init() {
	// "Register" this test to the main test registry
	TestList[NomadSecretTestType] = func() BenchmarkBuilder { return &NomadTest{} }
}

type NomadTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *NomadSecretTestConfig
	logger     hclog.Logger
}

type NomadSecretTestConfig struct {
	NomadConfig     *NomadConfig     `hcl:"nomad,block"`
	NomadRoleConfig *NomadRoleConfig `hcl:"role,block"`
}

type NomadConfig struct {
	Address            string `hcl:"address"`
	Token              string `hcl:"token,optional"`
	MaxTokenNameLength int    `hcl:"max_token_name_length,optional"`
	CaCert             string `hcl:"ca_cert,optional"`
	ClientCert         string `hcl:"client_cert,optional"`
	ClientKey          string `hcl:"client_key,optional"`
}

type NomadRoleConfig struct {
	Name     string   `hcl:"name,optional"`
	Policies []string `hcl:"policies,optional"`
	Global   bool     `hcl:"global,optional"`
	Type     string   `hcl:"type,optional"`
}

func (c *NomadTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *NomadSecretTestConfig `hcl:"config,block"`
	}{
		Config: &NomadSecretTestConfig{
			NomadConfig: &NomadConfig{
				Token: os.Getenv(NomadTokenEnvVar),
			},
			NomadRoleConfig: &NomadRoleConfig{
				Name: "benchmark-role",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	c.config = testConfig.Config

	// Ensure that the token has been set by either the environment variable or the config
	if c.config.NomadConfig.Token == "" {
		return fmt.Errorf("nomad token must be set")
	}
	return nil
}

func (c *NomadTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *NomadTest) Cleanup(client *api.Client) error {
	c.logger.Trace(cleanupLogMessage(c.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (c *NomadTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     NomadSecretTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *NomadTest) Setup(mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := c.config
	c.logger = targetLogger.Named(NomadSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	c.logger.Trace(mountLogMessage("secrets", "nomad", secretPath))
	err = topLevelConfig.Client.Sys().Mount(secretPath, &api.MountInput{
		Type: "nomad",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting nomad: %v", err)
	}

	setupLogger := c.logger.Named(secretPath)

	// Decode Nomad Config
	setupLogger.Trace(parsingConfigLogMessage("nomad"))
	nomadConfigData, err := structToMap(config.NomadConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing nomad config from struct: %v", err)
	}

	// Write Nomad config
	setupLogger.Trace(writingLogMessage("nomad config"))
	_, err = topLevelConfig.Client.Logical().Write(secretPath+"/config/access", nomadConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing nomad config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	nomadRoleConfigData, err := structToMap(config.NomadRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("nomad role"), "name", config.NomadRoleConfig.Name)
	_, err = topLevelConfig.Client.Logical().Write(secretPath+"/role/"+config.NomadRoleConfig.Name, nomadRoleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing nomad role: %v", err)
	}

	return &NomadTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(topLevelConfig.Client),
		roleName:   config.NomadRoleConfig.Name,
		logger:     c.logger,
	}, nil
}

func (c *NomadTest) Flags(fs *flag.FlagSet) {}
