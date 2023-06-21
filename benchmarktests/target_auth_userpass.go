// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
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
	// "Register" this test to the main test registry
	TestList[UserpassTestType] = func() BenchmarkBuilder { return &UserpassAuth{} }
}

type UserpassAuth struct {
	pathPrefix string
	user       string
	password   string
	header     http.Header
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

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
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

func (u *UserpassAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: UserpassAuthTestMethod,
		URL:    client.Address() + u.pathPrefix + "/login/" + u.user,
		Header: u.header,
		Body:   []byte(fmt.Sprintf(`{"password": "%s"}`, u.password)),
	}
}

func (u *UserpassAuth) Cleanup(client *api.Client) error {
	u.logger.Trace(cleanupLogMessage(u.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(u.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (u *UserpassAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     UserpassAuthTestMethod,
		pathPrefix: u.pathPrefix,
	}
}

func (u *UserpassAuth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	u.logger = targetLogger.Named(UserpassTestType)

	if randomMountName {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Userpass Auth Mount
	u.logger.Trace(mountLogMessage("auth", "userpass", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling userpass auth: %v", err)
	}

	setupLogger := u.logger.Named(authPath)

	// Decode Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("user"))
	userData, err := structToMap(u.config)
	if err != nil {
		return nil, fmt.Errorf("error parsing user config from struct: %v", err)
	}

	setupLogger.Trace(writingLogMessage("user config"))
	userPath := filepath.Join("auth", authPath, "users", u.config.Username)
	_, err = client.Logical().Write(userPath, userData)
	if err != nil {
		return nil, fmt.Errorf("error creating userpass user %q: %v", u.config.Username, err)
	}

	return &UserpassAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		user:       u.config.Username,
		password:   u.config.Password,
		logger:     u.logger,
	}, nil
}

func (u *UserpassAuth) Flags(fs *flag.FlagSet) {}
