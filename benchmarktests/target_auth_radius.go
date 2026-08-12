// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	RADIUSAuthTestType       = "radius_auth"
	RADIUSAuthTestMethod     = "POST"
	RADIUSTestUsernameEnvVar = VaultBenchmarkEnvVarPrefix + "RADIUS_TEST_USERNAME"
	RADIUSTestPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "RADIUS_TEST_PASSWORD"
	RADIUSSecretEnvVar       = VaultBenchmarkEnvVarPrefix + "RADIUS_SECRET"
)

func init() {
	TestList[RADIUSAuthTestType] = func() BenchmarkBuilder { return &RADIUSAuth{} }
}

type RADIUSAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	authUser   string
	config     *RADIUSAuthConfig
	logger     hclog.Logger
}

type RADIUSAuthConfig struct {
	RADIUSAuthMountConfig *RADIUSAuthMountConfig `hcl:"auth,block"`
	RADIUSAuthUserConfig *RADIUSAuthUserConfig `hcl:"test_user,block"`
}

type RADIUSAuthMountConfig struct {
	Host                     string   `hcl:"host,optional"`
	Port                     int      `hcl:"port,optional"`
	Secret                   string   `hcl:"secret,optional"`
	UnregisteredUserPolicies []string `hcl:"unregistered_user_policies,optional"`
	DialTimeout              int      `hcl:"dial_timeout,optional"`
	NASPort                  int      `hcl:"nas_port,optional"`
	TokenTTL                 string   `hcl:"token_ttl,optional"`
	TokenMaxTTL              string   `hcl:"token_max_ttl,optional"`
	TokenPolicies            []string `hcl:"token_policies,optional"`
	TokenBoundCIDRs          []string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL      string   `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy     bool     `hcl:"token_no_default_policy,optional"`
	TokenNumUses             int      `hcl:"token_num_uses,optional"`
	TokenPeriod              string   `hcl:"token_period,optional"`
	TokenType                string   `hcl:"token_type,optional"`
}

type RADIUSAuthUserConfig struct {
	Username string   `hcl:"username,optional"`
	Password string   `hcl:"password,optional"`
	Policies []string `hcl:"policies,optional"`
}

func (r *RADIUSAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *RADIUSAuthConfig `hcl:"config,block"`
	}{
		Config: &RADIUSAuthConfig{
			RADIUSAuthMountConfig: &RADIUSAuthMountConfig{
				Secret:      os.Getenv(RADIUSSecretEnvVar),
				DialTimeout: 10,
				NASPort:     10,
			},
			RADIUSAuthUserConfig: &RADIUSAuthUserConfig{
				Username: os.Getenv(RADIUSTestUsernameEnvVar),
				Password: os.Getenv(RADIUSTestPasswordEnvVar),
				Policies: []string{"default"},
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	r.config = testConfig.Config

	if r.config.RADIUSAuthMountConfig.Host == "" {
		return fmt.Errorf("no RADIUS host provided but required")
	}

	if r.config.RADIUSAuthMountConfig.Secret == "" {
		return fmt.Errorf("no RADIUS secret provided but required")
	}

	if r.config.RADIUSAuthUserConfig.Username == "" {
		return fmt.Errorf("no RADIUS username provided but required")
	}

	if r.config.RADIUSAuthUserConfig.Password == "" {
		return fmt.Errorf("no RADIUS password provided but required")
	}

	return nil
}

func (r *RADIUSAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	r.logger = targetLogger.Named(RADIUSAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	r.logger.Trace(mountLogMessage("auth", "radius", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "radius",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling radius auth: %v", err)
	}

	setupLogger := r.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("radius auth"))
	if err := writeStruct(client, "auth/"+authPath+"/config", r.config.RADIUSAuthMountConfig); err != nil {
		return nil, err
	}

	if len(r.config.RADIUSAuthUserConfig.Policies) > 0 {
		setupLogger.Trace(writingLogMessage("radius user config"), "username", r.config.RADIUSAuthUserConfig.Username)
		userConfig := map[string]any{
			"policies": strings.Join(r.config.RADIUSAuthUserConfig.Policies, ","),
		}
		userPath := "auth/" + authPath + "/users/" + r.config.RADIUSAuthUserConfig.Username
		_, err = client.Logical().Write(userPath, userConfig)
		if err != nil {
			return nil, fmt.Errorf("error writing radius user config: %v", err)
		}
	}

	return &RADIUSAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		authUser:   r.config.RADIUSAuthUserConfig.Username,
		body:       fmt.Appendf(nil, `{"password": "%s"}`, r.config.RADIUSAuthUserConfig.Password),
		logger:     r.logger,
	}, nil
}

func (r *RADIUSAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RADIUSAuthTestMethod,
		URL:    client.Address() + r.pathPrefix + "/login/" + r.authUser,
		Header: r.header,
		Body:   r.body,
	}
}

func (r *RADIUSAuth) Cleanup(client *api.Client) error {
	return cleanupMount(r.logger, client, r.pathPrefix)
}

func (r *RADIUSAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RADIUSAuthTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *RADIUSAuth) Flags(fs *flag.FlagSet) {}
