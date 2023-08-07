// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	GitHubAuthTestType      = "github_auth"
	GitHubAuthTestMethod    = "POST"
	GitHubAuthTestUserToken = VaultBenchmarkEnvVarPrefix + "GITHUB_TOKEN"
)

func init() {
	// "Register" this test to the main test registry
	TestList[GitHubAuthTestType] = func() BenchmarkBuilder { return &GitHubAuth{} }
}

type GitHubAuth struct {
	pathPrefix string
	token      string
	header     http.Header
	config     *GitHubAuthTestConfig
	logger     hclog.Logger
}

type GitHubAuthTestConfig struct {
	GitHubAuthConfig     *GitHubAuthConfig     `hcl:"auth,block"`
	GitHubTestUserConfig *GitHubTestUserConfig `hcl:"test_user,block"`
}

type GitHubAuthConfig struct {
	Organization         string `hcl:"organization"`
	OrganizationID       string `hcl:"organization_id,optional"`
	BaseURL              string `hcl:"base_url,optional"`
	TokenTTL             string `hcl:"token_ttl,optional"`
	TokenMaxTTL          string `hcl:"token_max_ttl,optional"`
	TokenPolicies        string `hcl:"token_policies,optional"`
	Policies             string `hcl:"policies,optional"`
	TokenBoundCIDRs      string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL  string `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy bool   `hcl:"token_no_default_policy,optional"`
	TokenNumUses         string `hcl:"token_num_uses,optional"`
	TokenPeriod          string `hcl:"token_period,optional"`
	TokenType            string `hcl:"token_type,optional"`
}

type GitHubTestUserConfig struct {
	Token string `hcl:"token,optional"`
}

func (g *GitHubAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *GitHubAuthTestConfig `hcl:"config,block"`
	}{
		Config: &GitHubAuthTestConfig{
			GitHubAuthConfig: &GitHubAuthConfig{},
			GitHubTestUserConfig: &GitHubTestUserConfig{
				Token: os.Getenv(GitHubAuthTestUserToken),
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	g.config = testConfig.Config

	// Empty Credentials check
	if g.config.GitHubTestUserConfig.Token == "" {
		return fmt.Errorf("no github test user token provided but required")
	}

	return nil
}

func (g *GitHubAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + g.pathPrefix + "/login",
		Header: g.header,
		Body:   []byte(fmt.Sprintf(`{"token": "%s"}`, g.token)),
	}
}

func (g *GitHubAuth) Cleanup(client *api.Client) error {
	g.logger.Trace(cleanupLogMessage(g.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(g.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (g *GitHubAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GitHubAuthTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (g *GitHubAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	g.logger = targetLogger.Named(GitHubAuthTestType)

	if topLevelConfig.RandomMounts {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create GitHub Auth mount
	g.logger.Trace(mountLogMessage("auth", "github", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "github",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling github: %v", err)
	}

	setupLogger := g.logger.Named(authPath)

	// Decode GitHubConfig struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("github auth"))
	ldapAuthConfig, err := structToMap(g.config.GitHubAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding github auth config from struct: %v", err)
	}

	// Write GitHub config
	setupLogger.Trace(writingLogMessage("github auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config", ldapAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing github auth config: %v", err)
	}

	return &GitHubAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		token:      g.config.GitHubTestUserConfig.Token,
		logger:     g.logger,
	}, nil
}

// Func Flags accepts a flag set to assign additional flags defined in the function
func (g *GitHubAuth) Flags(fs *flag.FlagSet) {}
