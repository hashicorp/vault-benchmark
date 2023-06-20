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
	LDAPAuthTestType               = "ldap_auth"
	LDAPAuthTestMethod             = "POST"
	LDAPAuthTestUserNameEnvVar     = VaultBenchmarkEnvVarPrefix + "LDAP_TEST_USERNAME"
	LDAPAuthTestUserPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "LDAP_TEST_PASSWORD"
	LDAPAuthBindPassEnvVar         = VaultBenchmarkEnvVarPrefix + "LDAP_BIND_PASS"
)

func init() {
	// "Register" this test to the main test registry
	TestList[LDAPAuthTestType] = func() BenchmarkBuilder { return &LDAPAuth{} }
}

type LDAPAuth struct {
	pathPrefix string
	authUser   string
	authPass   string
	header     http.Header
	config     *LDAPTestConfig
	logger     hclog.Logger
}

type LDAPTestConfig struct {
	Config *LDAPAuthTestConfig `hcl:"config,block"`
}

type LDAPAuthTestConfig struct {
	LDAPAuthConfig     *LDAPAuthConfig     `hcl:"auth,block"`
	LDAPTestUserConfig *LDAPTestUserConfig `hcl:"test_user,block"`
}

type LDAPAuthConfig struct {
	URL                  string   `hcl:"url"`
	CaseSensitiveNames   bool     `hcl:"case_sensitive_names,optional"`
	RequestTimeout       int      `hcl:"request_timeout,optional"`
	StartTLS             bool     `hcl:"starttls,optional"`
	TLSMinVersion        string   `hcl:"tls_min_version,optional"`
	TLSMaxVersion        string   `hcl:"tls_max_version,optional"`
	InsecureTLS          bool     `hcl:"insecure_tls,optional"`
	Certificate          string   `hcl:"certificate,optional"`
	ClientTLSCert        string   `hcl:"client_tls_cert,optional"`
	ClientTLSKey         string   `hcl:"client_tls_key,optional"`
	BindDN               string   `hcl:"binddn,optional"`
	BindPass             string   `hcl:"bindpass,optional"`
	UserDN               string   `hcl:"userdn,optional"`
	UserAttr             string   `hcl:"userattr,optional"`
	DiscoverDN           string   `hcl:"discoverdn,optional"`
	DenyNullBind         *bool    `hcl:"deny_null_bind,optional"`
	UPNDomain            string   `hcl:"upndomain,optional"`
	UserFilter           string   `hcl:"userfilter,optional"`
	AnonymousGroupSearch bool     `hcl:"anonymous_group_search,optional"`
	GroupFilter          string   `hcl:"groupfilter,optional"`
	GroupDN              string   `hcl:"groupdn,optional"`
	GroupAttr            string   `hcl:"groupattr,optional"`
	UsernameAsAlias      bool     `hcl:"username_as_alias,optional"`
	TokenTTL             int      `hcl:"token_ttl,optional"`
	TokenMaxTTL          int      `hcl:"token_max_ttl,optional"`
	TokenPolicies        []string `hcl:"token_policies,optional"`
	TokenBoundCIDRs      []string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL  int      `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy bool     `hcl:"token_no_default_policy,optional"`
	TokenNumUses         int      `hcl:"token_num_uses,optional"`
	TokenPeriod          string   `hcl:"token_period,optional"`
	TokenType            string   `hcl:"token_type,optional"`
	MaxPageSize          string   `hcl:"max_page_size,optional"`
}

type LDAPTestUserConfig struct {
	Username string `hcl:"username,optional"`
	Password string `hcl:"password,optional"`
}

func (l *LDAPAuth) ParseConfig(body hcl.Body) error {
	l.config = &LDAPTestConfig{
		Config: &LDAPAuthTestConfig{
			LDAPAuthConfig: &LDAPAuthConfig{
				BindPass: os.Getenv(LDAPAuthBindPassEnvVar),
			},
			LDAPTestUserConfig: &LDAPTestUserConfig{
				Username: os.Getenv(LDAPAuthTestUserNameEnvVar),
				Password: os.Getenv(LDAPAuthTestUserPasswordEnvVar),
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, l.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	// Empty Credentials check
	if l.config.Config.LDAPAuthConfig.BindPass == "" {
		return fmt.Errorf("no bindpass provided for vault to use")
	}

	if l.config.Config.LDAPTestUserConfig.Username == "" {
		return fmt.Errorf("no ldap test user username provided but required")
	}

	if l.config.Config.LDAPTestUserConfig.Password == "" {
		return fmt.Errorf("no password provided for ldap test user %v but required", l.config.Config.LDAPTestUserConfig.Username)
	}

	return nil
}

func (l *LDAPAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + l.pathPrefix + "/login/" + l.authUser,
		Header: l.header,
		Body:   []byte(fmt.Sprintf(`{"password": "%s"}`, l.authPass)),
	}
}

func (l *LDAPAuth) Cleanup(client *api.Client) error {
	l.logger.Trace(cleanupLogMessage(l.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(l.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (l *LDAPAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     LDAPAuthTestMethod,
		pathPrefix: l.pathPrefix,
	}
}

func (l *LDAPAuth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	config := l.config.Config
	l.logger = targetLogger.Named(LDAPAuthTestType)

	if randomMountName {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create LDAP Auth mount
	l.logger.Trace(mountLogMessage("auth", "ldap", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "ldap",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling ldap: %v", err)
	}

	setupLogger := l.logger.Named(authPath)

	// Decode LDAPConfig struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("ldap auth"))
	ldapAuthConfig, err := structToMap(config.LDAPAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding ldap auth config from struct: %v", err)
	}

	// Write LDAP config
	setupLogger.Trace(writingLogMessage("ldap auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config", ldapAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing ldap auth config: %v", err)
	}

	return &LDAPAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		authUser:   config.LDAPTestUserConfig.Username,
		authPass:   config.LDAPTestUserConfig.Password,
		logger:     l.logger,
	}, nil
}

// Func Flags accepts a flag set to assign additional flags defined in the function
func (l *LDAPAuth) Flags(fs *flag.FlagSet) {}
