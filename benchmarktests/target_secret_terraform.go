// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
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
	TerraformSecretTestType   = "terraform_secret"
	TerraformSecretTestMethod = "GET"
	TerraformTokenEnvVar      = VaultBenchmarkEnvVarPrefix + "TERRAFORM_TOKEN"
)

func init() {
	// "Register" this test to the main test registry
	TestList[TerraformSecretTestType] = func() BenchmarkBuilder { return &TerraformTest{} }
}

type TerraformTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *TerraformSecretTestConfig
	logger     hclog.Logger
}

type TerraformSecretTestConfig struct {
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

func (t *TerraformTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *TerraformSecretTestConfig `hcl:"config,block"`
	}{
		Config: &TerraformSecretTestConfig{
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

func (t *TerraformTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: TerraformSecretTestMethod,
		URL:    client.Address() + t.pathPrefix + "/creds/" + t.roleName,
		Header: t.header,
	}
}

func (t *TerraformTest) Cleanup(client *api.Client) error {
	t.logger.Trace(cleanupLogMessage(t.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(t.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (t *TerraformTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     TerraformSecretTestMethod,
		pathPrefix: t.pathPrefix,
	}
}

func (t *TerraformTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := t.config
	t.logger = targetLogger.Named(TerraformSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("error generating UUID: %v", err)
		}
	}

	t.logger.Trace(mountLogMessage("secrets", "terraform", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "terraform",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting terraform secrets engine: %v", err)
	}

	setupLogger := t.logger.Named(secretPath)

	// Decode Terraform Config
	setupLogger.Trace(parsingConfigLogMessage("terraform"))
	terraformConfigData, err := structToMap(config.TerraformConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing terraform config from struct: %v", err)
	}

	// Write Terraform config
	setupLogger.Trace(writingLogMessage("terraform config"))
	_, err = client.Logical().Write(secretPath+"/config", terraformConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing terraform config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	terraformRoleConfigData, err := structToMap(config.TerraformRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("terraform role"), "name", config.TerraformRoleConfig.Name)
	_, err = client.Logical().Write(secretPath+"/role/"+config.TerraformRoleConfig.Name, terraformRoleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing terraform role: %v", err)
	}

	return &TerraformTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.TerraformRoleConfig.Name,
		logger:     t.logger,
	}, nil
}

func (t *TerraformTest) Flags(fs *flag.FlagSet) {}
