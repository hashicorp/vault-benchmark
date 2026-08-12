// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	AWSAuthTestType   = "aws_auth"
	AWSAuthTestMethod = "POST"
	AWSAuthAccessKey  = VaultBenchmarkEnvVarPrefix + "AWS_ACCESS_KEY"
	AWSAuthSecretKey  = VaultBenchmarkEnvVarPrefix + "AWS_SECRET_KEY"

	// awsSigV4TTL is hardcoded by the AWS spec; awsBodyRefreshMargin ensures we
	// refresh before the signature window closes rather than after.
	awsSigV4TTL          = 15 * time.Minute
	awsBodyRefreshMargin = 1 * time.Minute
)

func init() {
	TestList[AWSAuthTestType] = func() BenchmarkBuilder { return &AWSAuth{} }
}

type AWSAuth struct {
	pathPrefix string
	header     http.Header
	login      cachedBody
	config     *AWSAuthConfig
	logger     hclog.Logger
}

type AWSAuthConfig struct {
	AWSAuthMountConfig *AWSAuthMountConfig `hcl:"auth,block"`
	AWSAuthUserConfig *AWSAuthUserConfig `hcl:"test_user,block"`
}

type AWSAuthMountConfig struct {
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

type AWSAuthUserConfig struct {
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
		Config *AWSAuthConfig `hcl:"config,block"`
	}{
		Config: &AWSAuthConfig{
			AWSAuthMountConfig: &AWSAuthMountConfig{
				AccessKey: os.Getenv(AWSAuthAccessKey),
				SecretKey: os.Getenv(AWSAuthSecretKey),
			},
			AWSAuthUserConfig: &AWSAuthUserConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	a.config = testConfig.Config

	if a.config.AWSAuthMountConfig.AccessKey == "" {
		return fmt.Errorf("no aws access_key provided but required")
	}

	if a.config.AWSAuthMountConfig.SecretKey == "" {
		return fmt.Errorf("no aws secret_key provided but required")
	}

	return nil
}

func (a *AWSAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	a.logger = targetLogger.Named(AWSAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	a.logger.Trace(mountLogMessage("auth", "aws", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "aws",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling aws: %v", err)
	}

	setupLogger := a.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("aws auth"))
	if err := writeStruct(client, "auth/"+authPath+"/config/client", a.config.AWSAuthMountConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("aws auth user"))
	if err := writeStruct(client, "auth/"+authPath+"/role/"+a.config.AWSAuthUserConfig.Role, a.config.AWSAuthUserConfig); err != nil {
		return nil, err
	}

	result := &AWSAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		config:     a.config,
		logger:     a.logger,
	}

	body, err := result.buildLoginBody()
	if err != nil {
		return nil, fmt.Errorf("error generating initial AWS login body: %w", err)
	}
	result.login.body = body
	result.login.expiry = time.Now().Add(awsSigV4TTL - awsBodyRefreshMargin)

	return result, nil
}

func (a *AWSAuth) Target(client *api.Client) vegeta.Target {
	a.login.mu.Lock()
	if time.Now().After(a.login.expiry) {
		if body, err := a.buildLoginBody(); err != nil {
			a.logger.Warn("failed to refresh AWS login body; using stale credentials", "error", err)
		} else {
			a.login.body = body
			a.login.expiry = time.Now().Add(awsSigV4TTL - awsBodyRefreshMargin)
		}
	}
	body := a.login.body
	a.login.mu.Unlock()

	return vegeta.Target{
		Method: AWSAuthTestMethod,
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   body,
	}
}

func (a *AWSAuth) Cleanup(client *api.Client) error {
	return cleanupMount(a.logger, client, a.pathPrefix)
}

func (a *AWSAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     AWSAuthTestMethod,
		pathPrefix: a.pathPrefix,
	}
}

func (a *AWSAuth) Flags(fs *flag.FlagSet) {}

func (a *AWSAuth) buildLoginBody() ([]byte, error) {
	creds, err := awsutil.RetrieveCreds(a.config.AWSAuthMountConfig.AccessKey, a.config.AWSAuthMountConfig.SecretKey, "", a.logger)
	if err != nil {
		return nil, err
	}

	region := a.config.AWSAuthMountConfig.STSRegion
	switch region {
	case "":
		region = awsutil.DefaultRegion
	case "auto":
		region = ""
	}

	loginData, err := awsutil.GenerateLoginData(creds, a.config.AWSAuthMountConfig.IAMServerIDHeaderValue, region, a.logger)
	if err != nil {
		return nil, err
	}
	if loginData == nil {
		return nil, fmt.Errorf("got nil response from GenerateLoginData")
	}
	loginData["role"] = a.config.AWSAuthUserConfig.Role
	return json.Marshal(loginData)
}
