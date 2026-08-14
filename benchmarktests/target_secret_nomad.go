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
	NomadSecretTestType   = "nomad_secret"
	NomadSecretTestMethod = "GET"
	NomadTokenEnvVar      = VaultBenchmarkEnvVarPrefix + "NOMAD_TOKEN"
)

func init() {
	TestList[NomadSecretTestType] = func() BenchmarkBuilder { return &NomadSecret{} }
}

type NomadSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *NomadSecretConfig
	logger     hclog.Logger
}

type NomadSecretConfig struct {
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

func (c *NomadSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *NomadSecretConfig `hcl:"config,block"`
	}{
		Config: &NomadSecretConfig{
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

	if c.config.NomadConfig.Token == "" {
		return fmt.Errorf("nomad token must be set")
	}
	return nil
}

func (c *NomadSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := c.config
	c.logger = targetLogger.Named(NomadSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	c.logger.Trace(mountLogMessage("secrets", "nomad", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "nomad",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting nomad: %v", err)
	}

	setupLogger := c.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("nomad"))
	if err := writeStruct(client, secretPath+"/config/access", config.NomadConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, secretPath+"/role/"+config.NomadRoleConfig.Name, config.NomadRoleConfig); err != nil {
		return nil, err
	}

	return &NomadSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.NomadRoleConfig.Name,
		logger:     c.logger,
	}, nil
}

func (c *NomadSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: NomadSecretTestMethod,
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *NomadSecret) Cleanup(client *api.Client) error {
	return cleanupMount(c.logger, client, c.pathPrefix)
}

func (c *NomadSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     NomadSecretTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *NomadSecret) Flags(fs *flag.FlagSet) {}
