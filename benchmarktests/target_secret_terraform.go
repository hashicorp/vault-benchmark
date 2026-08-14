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
	TerraformSecretTestType   = "terraform_secret"
	TerraformSecretTestMethod = "GET"
	TerraformTokenEnvVar      = VaultBenchmarkEnvVarPrefix + "TERRAFORM_TOKEN"
)

func init() {
	TestList[TerraformSecretTestType] = func() BenchmarkBuilder { return &TerraformSecret{} }
}

type TerraformSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *TerraformSecretConfig
	logger     hclog.Logger
}

type TerraformSecretConfig struct {
	TerraformConfig     *TerraformConfig     `hcl:"terraform,block"`
	TerraformRoleConfig *TerraformRoleConfig `hcl:"role,block"`
}

type TerraformConfig struct {
	Address string `hcl:"address,optional"`
	Token   string `hcl:"token,optional"`
}

type TerraformRoleConfig struct {
	Name           string `hcl:"name,optional"`
	Organization   string `hcl:"organization,optional"`
	TeamID         string `hcl:"team_id,optional"`
	UserID         string `hcl:"user_id,optional"`
	CredentialType string `hcl:"credential_type,optional"`
	Description    string `hcl:"description,optional"`
	TTL            string `hcl:"ttl,optional"`
	MaxTTL         string `hcl:"max_ttl,optional"`
}

func (t *TerraformSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *TerraformSecretConfig `hcl:"config,block"`
	}{
		Config: &TerraformSecretConfig{
			TerraformConfig: &TerraformConfig{
				Address: "https://app.terraform.io",
				Token:   os.Getenv(TerraformTokenEnvVar),
			},
			TerraformRoleConfig: &TerraformRoleConfig{
				Name:           "benchmark-role",
				CredentialType: "user",
				Description:    "Vault benchmark test role",
				TTL:            "1h",
				MaxTTL:         "24h",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	t.config = testConfig.Config

	return nil
}

func (t *TerraformSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := t.config
	t.logger = targetLogger.Named(TerraformSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	t.logger.Trace(mountLogMessage("secrets", "terraform", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "terraform",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting terraform secrets engine: %v", err)
	}

	setupLogger := t.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("terraform"))
	if err := writeStruct(client, secretPath+"/config", config.TerraformConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, secretPath+"/role/"+config.TerraformRoleConfig.Name, config.TerraformRoleConfig); err != nil {
		return nil, err
	}

	return &TerraformSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.TerraformRoleConfig.Name,
		logger:     t.logger,
	}, nil
}

func (t *TerraformSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: TerraformSecretTestMethod,
		URL:    client.Address() + t.pathPrefix + "/creds/" + t.roleName,
		Header: t.header,
	}
}

func (t *TerraformSecret) Cleanup(client *api.Client) error {
	return cleanupMount(t.logger, client, t.pathPrefix)
}

func (t *TerraformSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     TerraformSecretTestMethod,
		pathPrefix: t.pathPrefix,
	}
}

func (t *TerraformSecret) Flags(fs *flag.FlagSet) {}
