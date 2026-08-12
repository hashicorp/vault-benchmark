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
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	OktaAuthTestType   = "okta_auth"
	OktaAuthTestMethod = "POST"
)

func init() {
	TestList[OktaAuthTestType] = func() BenchmarkBuilder { return &OktaAuth{} }
}

type OktaAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	username   string
	config     *OktaAuthConfig
	logger     hclog.Logger
}

type OktaAuthConfig struct {
	OktaAuthMountConfig *OktaAuthMountConfig `hcl:"auth,block"`
	OktaAuthUserConfig *OktaAuthUserConfig `hcl:"test_user,block"`
}

type OktaAuthMountConfig struct {
	OrgName              string   `hcl:"org_name"`
	APIToken             string   `hcl:"api_token,optional"`
	BaseURL              string   `hcl:"base_url,optional"`
	BypassOktaMFA        bool     `hcl:"bypass_okta_mfa,optional"`
	TokenTTL             string   `hcl:"token_ttl,optional"`
	TokenMaxTTL          string   `hcl:"token_max_ttl,optional"`
	TokenPolicies        []string `hcl:"token_policies,optional"`
	Policies             []string `hcl:"policies,optional"`
	TokenBoundCIDRs      []string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL  string   `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy bool     `hcl:"token_no_default_policy,optional"`
	TokenNumUses         int      `hcl:"token_num_uses,optional"`
	TokenPeriod          string   `hcl:"token_period,optional"`
	TokenType            string   `hcl:"token_type,optional"`
}

type OktaAuthUserConfig struct {
	Username string   `hcl:"username"`
	Password string   `hcl:"password"`
	Groups   []string `hcl:"groups,optional"`
	Policies []string `hcl:"policies,optional"`
}

func (o *OktaAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *OktaAuthConfig `hcl:"config,block"`
	}{}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	o.config = testConfig.Config
	if o.config.OktaAuthMountConfig.OrgName == "" {
		return fmt.Errorf("no okta org_name provided but required")
	}
	if o.config.OktaAuthUserConfig.Username == "" {
		return fmt.Errorf("no okta username provided but required")
	}
	if o.config.OktaAuthUserConfig.Password == "" {
		return fmt.Errorf("no okta password provided but required")
	}
	return nil
}

func (o *OktaAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	o.logger = targetLogger.Named(OktaAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	o.logger.Trace(mountLogMessage("auth", "okta", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "okta",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling okta: %v", err)
	}

	setupLogger := o.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("okta auth"))
	if err := writeStruct(client, "auth/"+authPath+"/config", o.config.OktaAuthMountConfig); err != nil {
		return nil, err
	}

	if len(o.config.OktaAuthUserConfig.Groups) > 0 || len(o.config.OktaAuthUserConfig.Policies) > 0 {
		setupLogger.Trace(writingLogMessage("okta user config"))
		userConfig := map[string]any{}

		if len(o.config.OktaAuthUserConfig.Groups) > 0 {
			userConfig["groups"] = o.config.OktaAuthUserConfig.Groups
		}

		if len(o.config.OktaAuthUserConfig.Policies) > 0 {
			userConfig["policies"] = o.config.OktaAuthUserConfig.Policies
		}
		_, err = client.Logical().Write("auth/"+authPath+"/users/"+o.config.OktaAuthUserConfig.Username, userConfig)
		if err != nil {
			return nil, fmt.Errorf("error writing okta user config: %v", err)
		}
	}

	return &OktaAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		body:       fmt.Appendf(nil, `{"password": "%s"}`, o.config.OktaAuthUserConfig.Password),
		username:   o.config.OktaAuthUserConfig.Username,
		logger:     o.logger,
	}, nil
}

func (o *OktaAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: OktaAuthTestMethod,
		URL:    client.Address() + o.pathPrefix + "/login/" + o.username,
		Header: o.header,
		Body:   o.body,
	}
}

func (o *OktaAuth) Cleanup(client *api.Client) error {
	return cleanupMount(o.logger, client, o.pathPrefix)
}

func (o *OktaAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     OktaAuthTestMethod,
		pathPrefix: o.pathPrefix,
	}
}

func (o *OktaAuth) Flags(fs *flag.FlagSet) {}
