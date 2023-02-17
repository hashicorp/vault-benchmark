package benchmark_tests

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Override flags
var LDAPTestUserConfigJSON = flag.String("ldap_test_user_json", "", "when provided, the location of user credentials to test LDAP auth")

// Constants for test
const (
	LDAPAuthTestMethod = "POST"
	LDAPAuthConfigTag  = "ldap_auth_config"
)

func init() {
	// "Register" this test to the main test registry
	TestList["ldap_auth"] = func() BenchmarkBuilder { return &ldap_auth{} }
}

type ldap_auth struct {
	pathPrefix string
	authUser   string
	authPass   string
	header     http.Header
	config     *LDAPTestConfig
}

type LDAPTestConfig struct {
	Config *LDAPAuthTestConfig `hcl:"config,block"`
}

type LDAPAuthTestConfig struct {
	LDAPAuthConfig     *LDAPAuthConfig     `hcl:"ldap_auth_config,block"`
	LDAPTestUserConfig *LDAPTestUserConfig `hcl:"ldap_test_user_config,block"`
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
	DenyNullBind         bool     `hcl:"deny_null_bind,optional"`
	UPNDomain            string   `hcl:"upndomain,optional"`
	UserFilter           string   `hcl:"userfilter,optional"`
	AnonymousGroupSearch bool     `hcl:"anonymous_group_search,optional"`
	GroupFilter          string   `hcl:"group_filter,optional"`
	GroupDN              string   `hcl:"groupdn,optional"`
	GroupAttr            string   `hcl:"group_attr,optional"`
	UsernameAsAlias      bool     `hcl:"username_as_alias,optional"`
	TokenTTL             int      `hcl:"token_ttl,optional"`
	TokenMaxTTL          int      `hcl:"token_max_ttl,optional"`
	TokenPolicies        []string `hcl:"token_policies,optional"`
	TokenBoundCIDRs      []string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL  int      `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy bool     `hcl:"token_no_default_policy,optional"`
	TokenNumUses         int      `hcl:"token_num_uses,optional"`
	TokenPeriod          int      `hcl:"token_period,optional"`
	TokenType            string   `hcl:"token_type,optional"`
}

type LDAPTestUserConfig struct {
	Username string `hcl:"username"`
	Password string `hcl:"password"`
}

func (l *ldap_auth) ParseConfig(body hcl.Body) {
	l.config = &LDAPTestConfig{
		Config: &LDAPAuthTestConfig{
			LDAPAuthConfig:     &LDAPAuthConfig{},
			LDAPTestUserConfig: &LDAPTestUserConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, l.config)
	if diags.HasErrors() {
		fmt.Println(diags)
	}

	// Handle passed in JSON config
	if *LDAPTestUserConfigJSON != "" {
		err := l.config.Config.LDAPTestUserConfig.FromJSON(*LDAPTestUserConfigJSON)
		if err != nil {
			// Handle this error
			return
		}
	}
}

func (u *LDAPTestUserConfig) FromJSON(path string) error {
	if path == "" {
		return fmt.Errorf("no LDAP user config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(u); err != nil {
		return err
	}

	// Check for required fields
	switch {
	case u.Username == "":
		return fmt.Errorf("no username passed but is required")
	case u.Password == "":
		return fmt.Errorf("no password passed but is required")
	default:
		return nil
	}
}

func (l *ldap_auth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + l.pathPrefix + "/login/" + l.authUser,
		Header: l.header,
		Body:   []byte(fmt.Sprintf(`{"password": "%s"}`, l.authPass)),
	}
}

func (l *ldap_auth) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(l.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (l *ldap_auth) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     LDAPAuthTestMethod,
		pathPrefix: l.pathPrefix,
	}
	return tInfo
}

func (l *ldap_auth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	config := l.config.Config

	if randomMountName {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			panic("can't create UUID")
		}
	}

	// Create LDAP Auth mount
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "ldap",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling ldap: %v", err)
	}

	// Decode LDAPConfig struct into mapstructure to pass with request
	ldapAuthConfig, err := structToMap(config.LDAPAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding ldap auth config from struct: %v", err)
	}

	// Write LDAP config
	_, err = client.Logical().Write("auth/"+authPath+"/config", ldapAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing LDAP config: %v", err)
	}

	return &ldap_auth{
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		authUser:   config.LDAPTestUserConfig.Username,
		authPass:   config.LDAPTestUserConfig.Password,
	}, nil
}
