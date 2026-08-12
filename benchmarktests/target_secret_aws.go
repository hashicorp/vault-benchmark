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
	AWSSecretTestType   = "aws_secret"
	AWSSecretTestMethod = "GET"
	AWSSecretAccessKey  = VaultBenchmarkEnvVarPrefix + "AWS_ACCESS_KEY"
	AWSSecretSecretKey  = VaultBenchmarkEnvVarPrefix + "AWS_SECRET_KEY"
)

func init() {
	TestList[AWSSecretTestType] = func() BenchmarkBuilder { return &AWSSecret{} }
}

type AWSSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *AWSSecretConfig
	logger     hclog.Logger
}

type AWSSecretConfig struct {
	AWSConnectionConfig *AWSConnectionConfig `hcl:"connection,block"`
	AWSRoleConfig       *AWSRoleConfig       `hcl:"role,block"`
}

type AWSConnectionConfig struct {
	MaxRetries       int    `hcl:"max_retries,optional"`
	AccessKey        string `hcl:"access_key,optional"`
	SecretKey        string `hcl:"secret_key,optional"`
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

func (a *AWSSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *AWSSecretConfig `hcl:"config,block"`
	}{
		Config: &AWSSecretConfig{
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

func (a *AWSSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	a.logger = targetLogger.Named(AWSSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	a.logger.Trace(mountLogMessage("secrets", "aws", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "aws",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting aws secrets engine: %v", err)
	}

	setupLogger := a.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("aws connection"))
	if err := writeStruct(client, secretPath+"/config/root", a.config.AWSConnectionConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, secretPath+"/roles/"+a.config.AWSRoleConfig.Name, a.config.AWSRoleConfig); err != nil {
		return nil, err
	}

	return &AWSSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   a.config.AWSRoleConfig.Name,
		logger:     a.logger,
	}, nil
}

func (a *AWSSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: AWSSecretTestMethod,
		URL:    client.Address() + a.pathPrefix + "/creds/" + a.roleName,
		Header: a.header,
	}
}

func (a *AWSSecret) Cleanup(client *api.Client) error {
	return cleanupMount(a.logger, client, a.pathPrefix)
}

func (a *AWSSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     AWSSecretTestMethod,
		pathPrefix: a.pathPrefix,
	}
}

func (a *AWSSecret) Flags(fs *flag.FlagSet) {}
