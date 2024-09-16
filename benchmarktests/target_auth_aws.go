// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	AWSAuthTestType   = "aws_auth"
	AWSAuthTestMethod = "POST"
	AWSAuthAccessKey  = VaultBenchmarkEnvVarPrefix + "AWS_ACCESS_KEY"
	AWSAuthSecretKey  = VaultBenchmarkEnvVarPrefix + "AWS_SECRET_KEY"
)

func init() {
	// "Register" this test to the main test registry
	TestList[AWSAuthTestType] = func() BenchmarkBuilder { return &AWSAuth{} }
}

type AWSAuth struct {
	pathPrefix string
	loginData  map[string]interface{}
	header     http.Header
	config     *AWSAuthTestConfig
	logger     hclog.Logger
	sealWrap   bool
}

type AWSAuthTestConfig struct {
	AWSAuthConfig     *AWSAuthConfig     `hcl:"auth,block"`
	AWSTestUserConfig *AWSTestUserConfig `hcl:"test_user,block"`
	SealWrap          bool               `hcl:"seal_wrap,optional"`
}

type AWSAuthConfig struct {
	MaxRetries             int      `hcl:"max_retries,optional"`
	AccessKey              string   `hcl:"access_key,optional"`
	SecretKey              string   `hcl:"secret_key,optional"`
	Endpoint               string   `hcl:"endpoint,optional"`
	IAMEndpoint            string   `hcl:"iam_endpoint,optional"`
	STSEndpoint            string   `hcl:"sts_endpoint,optional"`
	STSRegion              string   `hcl:"sts_region,optional"`
	IAMServerIDHeaderValue string   `hcl:"iam_server_id_header_value,optional"`
	AllowedSTSHeaderValues []string `hcl:"allowed_sts_header_values,optional"`
}

type AWSTestUserConfig struct {
	Role                       string `hcl:"role"`
	AuthType                   string `hcl:"auth_type,optional"`
	BoundAMIID                 string `hcl:"bound_ami_id,optional"`
	BoundAccountID             string `hcl:"bound_account_id,optional"`
	BoundRegion                string `hcl:"bound_region,optional"`
	BoundVPCID                 string `hcl:"bound_vpc_id,optional"`
	BoundSubnetID              string `hcl:"bound_subnet_id,optional"`
	BoundIAMRoleARN            string `hcl:"bound_iam_role_arn,optional"`
	BoundIAMInstanceProfileARN string `hcl:"bound_iam_instance_profile_arn,optional"`
	BoundEC2InstanceARN        string `hcl:"bound_ec2_instance_arn,optional"`
	RoleTag                    string `hcl:"role_tag,optional"`
	BoundIAMPrincipalARN       string `hcl:"bound_iam_principal_arn,optional"`
	InferredEntityType         string `hcl:"inferred_entity_type,optional"`
	InferredAWSRegion          string `hcl:"inferred_aws_region,optional"`
	ResolveAWSUniqueIDs        bool   `hcl:"resolve_aws_unique_ids,optional"`
	AllowInstanceMigration     bool   `hcl:"allow_instance_migration,optional"`
	DisallowReauthentication   bool   `hcl:"disallow_reauthentication,optional"`
	TokenTTL                   string `hcl:"token_ttl,optional"`
	TokenMaxTTL                string `hcl:"token_max_ttl,optional"`
	TokenPolicies              string `hcl:"token_policies,optional"`
	Policies                   string `hcl:"policies,optional"`
	TokenBoundCIDRs            string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL        string `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy       bool   `hcl:"token_no_default_policy,optional"`
	TokenNumUses               int    `hcl:"token_num_uses,optional"`
	TokenPeriod                string `hcl:"token_period,optional"`
	TokenType                  string `hcl:"token_type,optional"`
}

func (a *AWSAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *AWSAuthTestConfig `hcl:"config,block"`
	}{
		Config: &AWSAuthTestConfig{
			AWSAuthConfig: &AWSAuthConfig{
				AccessKey: os.Getenv(AWSAuthAccessKey),
				SecretKey: os.Getenv(AWSAuthSecretKey),
			},
			AWSTestUserConfig: &AWSTestUserConfig{},
			SealWrap:          a.config.SealWrap,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	a.config = testConfig.Config

	// Empty Credentials check
	if a.config.AWSAuthConfig.AccessKey == "" {
		return fmt.Errorf("no aws access_key provided but required")
	}

	if a.config.AWSAuthConfig.SecretKey == "" {
		return fmt.Errorf("no aws secret_key provided but required")
	}

	return nil
}

func (a *AWSAuth) Target(client *api.Client) vegeta.Target {
	jsonData, _ := json.Marshal(a.loginData)
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   jsonData,
	}
}

func (a *AWSAuth) Cleanup(client *api.Client) error {
	a.logger.Trace(cleanupLogMessage(a.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(a.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (a *AWSAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     AWSAuthTestMethod,
		pathPrefix: a.pathPrefix,
	}
}

func (a *AWSAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	a.logger = targetLogger.Named(AWSAuthTestType)

	if topLevelConfig.RandomMounts {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create AWS Auth mount
	a.logger.Trace(mountLogMessage("auth", "aws", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type:     "aws",
		SealWrap: a.config.SealWrap,
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling aws: %v", err)
	}

	setupLogger := a.logger.Named(authPath)

	// Decode AWSConfig struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("aws auth"))
	awsAuthConfig, err := structToMap(a.config.AWSAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding aws auth config from struct: %v", err)
	}

	// Write AWS config
	setupLogger.Trace(writingLogMessage("aws auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config/client", awsAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing aws auth config: %v", err)
	}

	// Decode AWSTestUserConfig struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("aws auth user"))
	awsAuthUser, err := structToMap(a.config.AWSTestUserConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding aws auth user from struct: %v", err)
	}

	// Create AWS Test Role
	setupLogger.Trace(writingLogMessage("aws auth user config"))
	_, err = client.Logical().Write("auth/"+authPath+"/role/"+a.config.AWSTestUserConfig.Role, awsAuthUser)
	if err != nil {
		return nil, fmt.Errorf("error writing aws auth user: %v", err)
	}

	headerValue := a.config.AWSAuthConfig.IAMServerIDHeaderValue

	creds, err := awsutil.RetrieveCreds(a.config.AWSAuthConfig.AccessKey, a.config.AWSAuthConfig.SecretKey, "", a.logger)
	if err != nil {
		return nil, err
	}

	region := a.config.AWSAuthConfig.STSRegion
	switch region {
	case "":
		// The CLI has always defaulted to "us-east-1" if a region is not provided.
		region = awsutil.DefaultRegion
	case "auto":
		// Beginning in 1.10 we also accept the "auto" value, which uses the region detection logic in
		// awsutil.GetRegion() to determine the region. That behavior is triggered when region = "".
		region = ""
	}

	loginData, err := awsutil.GenerateLoginData(creds, headerValue, region, a.logger)
	if err != nil {
		return nil, err
	}
	if loginData == nil {
		return nil, fmt.Errorf("got nil response from GenerateLoginData")
	}
	loginData["role"] = a.config.AWSTestUserConfig.Role // add role to login data

	return &AWSAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		loginData:  loginData,
		logger:     a.logger,
	}, nil
}

// Func Flags accepts a flag set to assign additional flags defined in the function
func (a *AWSAuth) Flags(fs *flag.FlagSet) {}
