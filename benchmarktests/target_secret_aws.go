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
	AWSSecretTestType   = "aws_secret"
	AWSSecretTestMethod = "GET"
	AWSSecretAccessKey  = VaultBenchmarkEnvVarPrefix + "AWS_ACCESS_KEY"
	AWSSecretSecretKey  = VaultBenchmarkEnvVarPrefix + "AWS_SECRET_KEY"
)

func init() {
	// "Register" this test to the main test registry
	TestList[AWSSecretTestType] = func() BenchmarkBuilder { return &AWSTest{} }
}

type AWSTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *AWSSecretTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type AWSSecretTestConfig struct {
	AWSConnectionConfig *AWSConnectionConfig `hcl:"connection,block"`
	AWSRoleConfig       *AWSRoleConfig       `hcl:"role,block"`
}

type AWSConnectionConfig struct {
	MaxRetries       int    `hcl:"max_retries,optional"`
	AccessKey        string `hcl:"access_key"`
	SecretKey        string `hcl:"secret_key"`
	Region           string `hcl:"region,optional"`
	IAMEndpoint      string `hcl:"iam_endpoint,optional"`
	STSEndpoint      string `hcl:"sts_endpoint,optional"`
	UsernameTemplate string `hcl:"username_template,optional"`
}

type AWSRoleConfig struct {
	Name                   string `hcl:"name,optional"`
	CredentialType         string `hcl:"credential_type,optional"`
	RoleARNs               string `hcl:"role_arns,optional"`
	PolicyARNs             string `hcl:"policy_arns,optional"`
	PolicyDocument         string `hcl:"policy_document,optional"`
	IAM_groups             string `hcl:"iam_groups,optional"`
	IAM_tags               string `hcl:"iam_tags,optional"`
	DefaultSTSTTL          string `hcl:"default_sts_ttl,optional"`
	MaxSTSTTL              string `hcl:"max_sts_ttl,optional"`
	UserPath               string `hcl:"user_path,optional"`
	PermissionsBoundaryARN string `hcl:"permissions_boundary_arn,optional"`
}

func (a *AWSTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *AWSSecretTestConfig `hcl:"config,block"`
	}{
		Config: &AWSSecretTestConfig{
			AWSConnectionConfig: &AWSConnectionConfig{
				AccessKey: os.Getenv(AWSSecretAccessKey),
				SecretKey: os.Getenv(AWSSecretSecretKey),
			},
			AWSRoleConfig: &AWSRoleConfig{
				Name:           "benchmark-role",
				CredentialType: "iam_user",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	a.config = testConfig.Config

	if a.config.AWSConnectionConfig.AccessKey == "" {
		return fmt.Errorf("no aws access_key provided but required")
	}

	if a.config.AWSConnectionConfig.SecretKey == "" {
		return fmt.Errorf("no aws secret_key provided but required")
	}

	return nil
}

func (a *AWSTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: AWSSecretTestMethod,
		URL:    client.Address() + a.pathPrefix + "/creds/" + a.roleName,
		Header: a.header,
	}
}

func (a *AWSTest) Cleanup(client *api.Client) error {
	a.logger.Trace(cleanupLogMessage(a.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(a.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (a *AWSTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     AWSSecretTestMethod,
		pathPrefix: a.pathPrefix,
	}
}

func (a *AWSTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	a.logger = targetLogger.Named(AWSSecretTestType)

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	a.logger.Trace(mountLogMessage("secrets", "aws", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "aws",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting aws secrets engine: %v", err)
	}

	setupLogger := a.logger.Named(secretPath)

	// Decode AWS Connection Config
	setupLogger.Trace(parsingConfigLogMessage("aws connection"))
	connectionConfigData, err := structToMap(a.config.AWSConnectionConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing aws connection config from struct: %v", err)
	}

	// Write connection config
	setupLogger.Trace(writingLogMessage("aws connection config"))
	_, err = client.Logical().Write(secretPath+"/config/root", connectionConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing aws connection config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleConfigData, err := structToMap(a.config.AWSRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("aws role"), "name", a.config.AWSRoleConfig.Name)
	_, err = client.Logical().Write(secretPath+"/roles/"+a.config.AWSRoleConfig.Name, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing aws role: %v", err)
	}

	return &AWSTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   a.config.AWSRoleConfig.Name,
		logger:     a.logger,
	}, nil
}

func (m *AWSTest) Flags(fs *flag.FlagSet) {}
