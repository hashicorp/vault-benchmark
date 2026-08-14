// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	GitHubAuthTestType      = "github_auth"
	GitHubAuthTestMethod    = "POST"
	GitHubAuthTestUserToken = VaultBenchmarkEnvVarPrefix + "GITHUB_TOKEN"
)

func init() {
	TestList[GitHubAuthTestType] = func() BenchmarkBuilder { return &GitHubAuth{} }
}

type GitHubAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	config     *GitHubAuthConfig
	logger     hclog.Logger
}

type GitHubAuthConfig struct {
	GitHubAuthMountConfig *GitHubAuthMountConfig `hcl:"auth,block"`
	GitHubAuthUserConfig *GitHubAuthUserConfig `hcl:"test_user,block"`
}

type GitHubAuthMountConfig struct {
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

type GitHubAuthUserConfig struct {
	Token string `hcl:"token,optional"`
}

func (g *GitHubAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *GitHubAuthConfig `hcl:"config,block"`
	}{
		Config: &GitHubAuthConfig{
			GitHubAuthMountConfig: &GitHubAuthMountConfig{},
			GitHubAuthUserConfig: &GitHubAuthUserConfig{
				Token: os.Getenv(GitHubAuthTestUserToken),
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	g.config = testConfig.Config

	if g.config.GitHubAuthUserConfig.Token == "" {
		return fmt.Errorf("no github test user token provided but required")
	}

	return nil
}

func (g *GitHubAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	g.logger = targetLogger.Named(GitHubAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	g.logger.Trace(mountLogMessage("auth", "github", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "github",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling github: %v", err)
	}

	setupLogger := g.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("github auth"))
	if err := writeStruct(client, "auth/"+authPath+"/config", g.config.GitHubAuthMountConfig); err != nil {
		return nil, err
	}

	return &GitHubAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		body:       fmt.Appendf(nil, `{"token": "%s"}`, g.config.GitHubAuthUserConfig.Token),
		logger:     g.logger,
	}, nil
}

func (g *GitHubAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: GitHubAuthTestMethod,
		URL:    client.Address() + g.pathPrefix + "/login",
		Header: g.header,
		Body:   g.body,
	}
}

func (g *GitHubAuth) Cleanup(client *api.Client) error {
	return cleanupMount(g.logger, client, g.pathPrefix)
}

func (g *GitHubAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GitHubAuthTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (g *GitHubAuth) Flags(fs *flag.FlagSet) {}
