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
	RADIUSAuthTestType       = "radius_auth"
	RADIUSAuthTestMethod     = "POST"
	RADIUSTestUsernameEnvVar = VaultBenchmarkEnvVarPrefix + "RADIUS_TEST_USERNAME"
	RADIUSTestPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "RADIUS_TEST_PASSWORD"
	RADIUSSecretEnvVar       = VaultBenchmarkEnvVarPrefix + "RADIUS_SECRET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[RADIUSAuthTestType] = func() BenchmarkBuilder { return &RADIUSAuth{} }
}

type RADIUSAuth struct {
	pathPrefix string
	authUser   string
	authPass   string
	header     http.Header
	config     *RADIUSAuthTestConfig
	logger     hclog.Logger
}

type RADIUSAuthTestConfig struct {
	RADIUSAuthConfig     *RADIUSAuthConfig     `hcl:"auth,block"`
	RADIUSTestUserConfig *RADIUSTestUserConfig `hcl:"test_user,block"`
}

type RADIUSAuthConfig struct {
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

type RADIUSTestUserConfig struct {
	Username string   `hcl:"username,optional"`
	Password string   `hcl:"password,optional"`
	Policies []string `hcl:"policies,optional"`
}

func (r *RADIUSAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *RADIUSAuthTestConfig `hcl:"config,block"`
	}{
		Config: &RADIUSAuthTestConfig{
			RADIUSAuthConfig: &RADIUSAuthConfig{
				Secret:      os.Getenv(RADIUSSecretEnvVar),
				DialTimeout: 10,
				NASPort:     10,
			},
			RADIUSTestUserConfig: &RADIUSTestUserConfig{
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

	// Validation first
	if r.config.RADIUSAuthConfig.Host == "" {
		return fmt.Errorf("no RADIUS host provided but required")
	}

	// Provide defaults if environment variables are not set
	if r.config.RADIUSAuthConfig.Secret == "" {
		return fmt.Errorf("no RADIUS secret provided but required")
	}

	if r.config.RADIUSTestUserConfig.Username == "" {
		return fmt.Errorf("no RADIUS username provided but required")
	}

	if r.config.RADIUSTestUserConfig.Password == "" {
		return fmt.Errorf("no RADIUS password provided but required")
	}

	return nil
}

func (r *RADIUSAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RADIUSAuthTestMethod,
		URL:    client.Address() + r.pathPrefix + "/login/" + r.authUser,
		Header: r.header,
		Body:   []byte(fmt.Sprintf(`{"password": "%s"}`, r.authPass)),
	}
}

func (r *RADIUSAuth) Cleanup(client *api.Client) error {
	r.logger.Trace(cleanupLogMessage(r.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (r *RADIUSAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RADIUSAuthTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *RADIUSAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	r.logger = targetLogger.Named(RADIUSAuthTestType)

	if topLevelConfig.RandomMounts {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create RADIUS Auth mount
	r.logger.Trace(mountLogMessage("auth", "radius", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "radius",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling radius auth: %v", err)
	}

	setupLogger := r.logger.Named(authPath)

	// Decode RADIUSAuthConfig struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("radius auth"))
	radiusAuthConfig, err := structToMap(r.config.RADIUSAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding radius auth config from struct: %v", err)
	}

	// Write RADIUS config
	setupLogger.Trace(writingLogMessage("radius auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config", radiusAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing radius auth config: %v", err)
	}

	// Register the test user with Vault RADIUS auth
	if len(r.config.RADIUSTestUserConfig.Policies) > 0 {
		setupLogger.Trace(writingLogMessage("radius user config"), "username", r.config.RADIUSTestUserConfig.Username)
		userConfig := map[string]interface{}{
			"policies": strings.Join(r.config.RADIUSTestUserConfig.Policies, ","),
		}
		userPath := "auth/" + authPath + "/users/" + r.config.RADIUSTestUserConfig.Username
		_, err = client.Logical().Write(userPath, userConfig)
		if err != nil {
			return nil, fmt.Errorf("error writing radius user config: %v", err)
		}
	}

	return &RADIUSAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		authUser:   r.config.RADIUSTestUserConfig.Username,
		authPass:   r.config.RADIUSTestUserConfig.Password,
		logger:     r.logger,
	}, nil
}

// Func Flags accepts a flag set to assign additional flags defined in the function
func (r *RADIUSAuth) Flags(fs *flag.FlagSet) {}
