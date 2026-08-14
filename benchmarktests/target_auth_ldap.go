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
	LDAPAuthTestType               = "ldap_auth"
	LDAPAuthTestMethod             = "POST"
	LDAPAuthTestUserNameEnvVar     = VaultBenchmarkEnvVarPrefix + "LDAP_TEST_USERNAME"
	LDAPAuthTestUserPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "LDAP_TEST_PASSWORD"
	LDAPAuthBindPassEnvVar         = VaultBenchmarkEnvVarPrefix + "LDAP_BIND_PASS"
)

func init() {
	TestList[LDAPAuthTestType] = func() BenchmarkBuilder { return &LDAPAuth{} }
}

type LDAPAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	authUser   string
	config     *LDAPAuthConfig
	logger     hclog.Logger
}

type LDAPAuthConfig struct {
	LDAPAuthMountConfig *LDAPAuthMountConfig `hcl:"auth,block"`
	LDAPAuthUserConfig *LDAPAuthUserConfig `hcl:"test_user,block"`
}

type LDAPAuthMountConfig struct {
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

type LDAPAuthUserConfig struct {
	Username string `hcl:"username,optional"`
	Password string `hcl:"password,optional"`
}

func (l *LDAPAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *LDAPAuthConfig `hcl:"config,block"`
	}{
		Config: &LDAPAuthConfig{
			LDAPAuthMountConfig: &LDAPAuthMountConfig{
				BindPass: os.Getenv(LDAPAuthBindPassEnvVar),
			},
			LDAPAuthUserConfig: &LDAPAuthUserConfig{
				Username: os.Getenv(LDAPAuthTestUserNameEnvVar),
				Password: os.Getenv(LDAPAuthTestUserPasswordEnvVar),
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	l.config = testConfig.Config

	if l.config.LDAPAuthMountConfig.BindPass == "" {
		return fmt.Errorf("no bindpass provided for vault to use")
	}

	if l.config.LDAPAuthUserConfig.Username == "" {
		return fmt.Errorf("no ldap test user username provided but required")
	}

	if l.config.LDAPAuthUserConfig.Password == "" {
		return fmt.Errorf("no password provided for ldap test user %v but required", l.config.LDAPAuthUserConfig.Username)
	}

	return nil
}

func (l *LDAPAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	l.logger = targetLogger.Named(LDAPAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	l.logger.Trace(mountLogMessage("auth", "ldap", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "ldap",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling ldap: %v", err)
	}

	setupLogger := l.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("ldap auth"))
	if err := writeStruct(client, "auth/"+authPath+"/config", l.config.LDAPAuthMountConfig); err != nil {
		return nil, err
	}

	return &LDAPAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		authUser:   l.config.LDAPAuthUserConfig.Username,
		body:       fmt.Appendf(nil, `{"password": "%s"}`, l.config.LDAPAuthUserConfig.Password),
		logger:     l.logger,
	}, nil
}

func (l *LDAPAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: LDAPAuthTestMethod,
		URL:    client.Address() + l.pathPrefix + "/login/" + l.authUser,
		Header: l.header,
		Body:   l.body,
	}
}

func (l *LDAPAuth) Cleanup(client *api.Client) error {
	return cleanupMount(l.logger, client, l.pathPrefix)
}

func (l *LDAPAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     LDAPAuthTestMethod,
		pathPrefix: l.pathPrefix,
	}
}

func (l *LDAPAuth) Flags(fs *flag.FlagSet) {}
