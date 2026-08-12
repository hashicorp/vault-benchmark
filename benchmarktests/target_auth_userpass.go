// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	"github.com/sethvargo/go-password/password"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	UserpassTestType       = "userpass_auth"
	UserpassAuthTestMethod = "POST"
)

func init() {
	TestList[UserpassTestType] = func() BenchmarkBuilder { return &UserpassAuth{} }
}

type UserpassAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	user       string
	config     *UserpassAuthConfig
	logger     hclog.Logger
}

type UserpassAuthConfig struct {
	Username             string   `hcl:"username,optional"`
	Password             string   `hcl:"password,optional"`
	TokenTTL             string   `hcl:"token_ttl,optional"`
	TokenMaxTTL          string   `hcl:"token_max_ttl,optional"`
	TokenPolicies        []string `hcl:"token_policies,optional"`
	TokenBoundCidrs      []string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL  string   `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy bool     `hcl:"token_no_default_policy,optional"`
	TokenNumUses         int      `hcl:"token_num_uses,optional"`
	TokenPeriod          string   `hcl:"token_period,optional"`
	TokenType            string   `hcl:"token_type,optional"`
}

func (u *UserpassAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *UserpassAuthConfig `hcl:"config,block"`
	}{
		Config: &UserpassAuthConfig{
			Username: "benchmark-user",
			Password: password.MustGenerate(64, 10, 0, false, true),
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	u.config = testConfig.Config
	return nil
}

func (u *UserpassAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	u.logger = targetLogger.Named(UserpassTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	u.logger.Trace(mountLogMessage("auth", "userpass", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling userpass auth: %v", err)
	}

	setupLogger := u.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("user"))
	if err := writeStruct(client, filepath.Join("auth", authPath, "users", u.config.Username), u.config); err != nil {
		return nil, err
	}

	return &UserpassAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		user:       u.config.Username,
		body:       fmt.Appendf(nil, `{"password": "%s"}`, u.config.Password),
		logger:     u.logger,
	}, nil
}

func (u *UserpassAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: UserpassAuthTestMethod,
		URL:    client.Address() + u.pathPrefix + "/login/" + u.user,
		Header: u.header,
		Body:   u.body,
	}
}

func (u *UserpassAuth) Cleanup(client *api.Client) error {
	return cleanupMount(u.logger, client, u.pathPrefix)
}

func (u *UserpassAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     UserpassAuthTestMethod,
		pathPrefix: u.pathPrefix,
	}
}

func (u *UserpassAuth) Flags(fs *flag.FlagSet) {}
