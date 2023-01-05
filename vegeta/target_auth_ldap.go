package vegeta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type ldaptest struct {
	pathPrefix string
	authUser   string
	authPass   string
	header     http.Header
}

type LDAPAuthConfig struct {
	URL                  string   `json:"url"`
	CaseSensitiveNames   bool     `json:"case_sensitive_names"`
	RequestTimeout       int      `json:"request_timeout"`
	StartTLS             bool     `json:"starttls"`
	TLSMinVersion        string   `json:"tls_min_version"`
	TLSMaxVersion        string   `json:"tls_max_version"`
	InsecureTLS          bool     `json:"insecure_tls"`
	Certificate          string   `json:"certificate"`
	ClientTLSCert        string   `json:"client_tls_cert"`
	ClientTLSKey         string   `json:"client_tls_key"`
	BindDN               string   `json:"binddn"`
	BindPass             string   `json:"bindpass"`
	UserDN               string   `json:"userdn"`
	UserAttr             string   `json:"userattr"`
	DiscoverDN           string   `json:"discoverdn"`
	DenyNullBind         bool     `json:"deny_null_bind"`
	UPNDomain            string   `json:"upndomain"`
	UserFilter           string   `json:"userfilter"`
	AnonymousGroupSearch bool     `json:"anonymous_group_search"`
	GroupFilter          string   `json:"group_filter"`
	GroupDN              string   `json:"groupdn"`
	GroupAttr            string   `json:"groupattr"`
	UsernameAsAlias      bool     `json:"username_as_alias"`
	TokenTTL             int      `json:"token_ttl"`
	TokenMaxTTL          int      `json:"token_max_ttl"`
	TokenPolicies        []string `json:"token_policies"`
	TokenBoundCIDRs      []string `json:"token_bound_cidrs"`
	TokenExplicitMaxTTL  int      `json:"token_explicit_max_ttl"`
	TokenNoDefaultPolicy bool     `json:"token_no_default_policy"`
	TokenNumUses         int      `json:"token_num_uses"`
	TokenPeriod          int      `json:"token_period"`
	TokenType            string   `json:"token_type"`
}

type LDAPTestUserConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *LDAPAuthConfig) FromJSON(path string) error {
	// Set Defaults
	c.TLSMinVersion = "tls12"
	c.TLSMaxVersion = "tls12"

	if path == "" {
		return fmt.Errorf("no LDAP Config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(c); err != nil {
		return err
	}

	// Check for required fields
	switch {
	case c.URL == "":
		return fmt.Errorf("no LDAP server url provided but is required")
	case c.GroupDN == "":
		return fmt.Errorf("no groupdn provided but is required")
	default:
		return nil
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

func (l *ldaptest) login(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + l.pathPrefix + "/login/" + l.authUser,
		Header: l.header,
		Body:   []byte(fmt.Sprintf(`{"password": "%s"}`, l.authPass)),
	}
}

func (l *ldaptest) cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(l.pathPrefix, "/v1/", "/sys/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupLDAPAuth(client *api.Client, randomMounts bool, config *LDAPAuthConfig, testUserConfig *LDAPTestUserConfig) (*ldaptest, error) {
	authPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		authPath = "ldap"
	}

	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "ldap",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling ldap: %v", err)
	}

	// Write LDAP config
	_, err = client.Logical().Write("auth/"+authPath+"/config", map[string]interface{}{
		"url":                     config.URL,
		"case_sensitive_names":    config.CaseSensitiveNames,
		"request_timeout":         config.RequestTimeout,
		"starttls":                config.StartTLS,
		"tls_min_version":         config.TLSMinVersion,
		"tls_max_version":         config.TLSMaxVersion,
		"insecure_tls":            config.InsecureTLS,
		"certificate":             config.Certificate,
		"client_tls_cert":         config.ClientTLSCert,
		"client_tls_key":          config.ClientTLSKey,
		"binddn":                  config.BindDN,
		"bindpass":                config.BindPass,
		"userdn":                  config.UserDN,
		"userattr":                config.UserAttr,
		"discoverdn":              config.DiscoverDN,
		"deny_null_bind":          config.DenyNullBind,
		"upndomain":               config.UPNDomain,
		"userfilter":              config.UserFilter,
		"anonymous_group_search":  config.AnonymousGroupSearch,
		"group_filter":            config.GroupFilter,
		"groupdn":                 config.GroupDN,
		"groupattr":               config.GroupAttr,
		"username_as_alias":       config.UsernameAsAlias,
		"token_ttl":               config.TokenTTL,
		"token_max_ttl":           config.TokenMaxTTL,
		"token_policies":          config.TokenPolicies,
		"token_bound_cidrs":       config.TokenBoundCIDRs,
		"token_explicit_max_ttl":  config.TokenExplicitMaxTTL,
		"token_no_default_policy": config.TokenNoDefaultPolicy,
		"token_num_uses":          config.TokenNumUses,
		"token_period":            config.TokenPeriod,
		"token_type":              config.TokenType,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing LDAP config: %v", err)
	}

	return &ldaptest{
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		authUser:   testUserConfig.Username,
		authPass:   testUserConfig.Password,
	}, nil
}
