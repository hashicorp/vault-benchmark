package benchmark_tests

import (
	"flag"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Override flags
var PctApproleLogin = flag.Int("pct_approle_login", 0, "percent of requests that are approle logins")

func init() {
	// "Register" this test to the main test registry
	TestList["approle_auth"] = func() BenchmarkBuilder { return &approle_auth{} }
}

// Approle Auth Test Struct
type approle_auth struct {
	pathPrefix string
	role       string
	roleID     string
	header     http.Header
	secretID   string
	config     *TestConfig
}

// Main Config Struct
type TestConfig struct {
	Config *ApproleAuthTestConfig `hcl:"config,block"`
}

// Intermediary struct to assist with HCL decoding
type ApproleAuthTestConfig struct {
	RoleConfig     *RoleConfig     `hcl:"role_config,block"`
	SecretIDConfig *SecretIDConfig `hcl:"secret_id_config,block"`
}

// AppRole Role Config
type RoleConfig struct {
	Name                 string   `hcl:"role_name" mapstructure:"role_name"`
	BindSecretID         bool     `hcl:"bind_secret_id,optional" mapstructure:"bind_secret_id,omitempty"`
	SecretIDBoundCIDRS   []string `hcl:"secret_id_bound_cidrs,optional" mapstructure:"secret_id_bound_cidrs,omitempty"`
	SecredIDNumUses      int      `hcl:"secret_id_num_uses,optional" mapstructure:"secret_id_num_uses,omitempty"`
	SecretIDTTL          string   `hcl:"secret_id_ttl,optional" mapstructure:"secret_id_ttl,omitempty"`
	LocalSecretIDs       bool     `hcl:"local_secret_ids,optional" mapstructure:"local_secret_ids,omitempty"`
	TokenTTL             string   `hcl:"token_ttl,optional" mapstructure:"token_ttl,omitempty"`
	TokenMaxTTL          string   `hcl:"token_max_ttl,optional" mapstructure:"token_max_ttl,omitempty"`
	TokenPolicies        []string `hcl:"token_policies,optional" mapstructure:"token_policies,omitempty"`
	Policies             []string `hcl:"policies,optional" mapstructure:"policies,omitempty"`
	TokenBoundCIDRs      []string `hcl:"token_bound_cidrs,optional" mapstructure:"token_bound_cidrs,omitempty"`
	TokenExplicitMaxTTL  string   `hcl:"token_explicit_max_ttl,optional" mapstructure:"token_explicit_max_ttl,omitempty"`
	TokenNoDefaultPolicy bool     `hcl:"token_no_default_policy,optional" mapstructure:"token_no_default_policy,omitempty"`
	TokenNumUses         int      `hcl:"token_num_uses,optional" mapstructure:"token_num_uses,omitempty"`
	TokenPeriod          string   `hcl:"token_period,optional" mapstructure:"token_period,omitempty"`
	TokenType            string   `hcl:"token_type,optional" mapstructure:"token_type,omitempty"`
}

// AppRole SecretID Config
type SecretIDConfig struct {
	Metadata        string   `hcl:"metadata,optional" mapstructure:"metadata,omitempty"`
	CIDRList        []string `hcl:"cidr_list,optional" mapstructure:"cidr_list,omitempty"`
	NumUses         int      `hcl:"num_uses,optional" mapstructure:"num_uses,omitempty"`
	TTL             string   `hcl:"ttl,optional" mapstructure:"ttl,omitempty"`
	TokenBoundCIDRs []string `hcl:"token_bound_cidrs,optional" mapstructure:"token_bound_cidrs,omitempty"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (a *approle_auth) ParseConfig(body hcl.Body) {
	a.config = &TestConfig{
		Config: &ApproleAuthTestConfig{
			RoleConfig: &RoleConfig{
				Name: "benchmark-role",
			},
			SecretIDConfig: &SecretIDConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, a.config)
	if diags.HasErrors() {
		fmt.Println(diags)
	}
}

func (a *approle_auth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   []byte(fmt.Sprintf(`{"role_id": "%s", "secret_id": "%s"}`, a.roleID, a.secretID)),
	}
}

func (a *approle_auth) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(a.pathPrefix, "/v1/", "/sys/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (a *approle_auth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     "POST",
		pathPrefix: a.pathPrefix,
	}
}

func (a *approle_auth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	config := a.config.Config

	if randomMountName {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			panic("can't create UUID")
		}
	}

	// Create AppRole Auth Mount
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling approle: %v", err)
	}

	// Decode RoleConfig struct into mapstructure to pass with request
	roleData := make(map[string]interface{})
	err = mapstructure.Decode(config.RoleConfig, &roleData)
	if err != nil {
		return nil, fmt.Errorf("error decoding role config from struct: %v", err)
	}

	// Set Up Role
	rolePath := filepath.Join("auth", authPath, "role", config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error creating approle role %q: %v", config.RoleConfig.Name, err)
	}

	// Get Role ID
	roleSecret, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return nil, fmt.Errorf("error reading approle role_id: %v", err)
	}

	// Decode SecretIDConfig struct into map to pass with request
	secretIDData := make(map[string]interface{})
	err = mapstructure.Decode(config.SecretIDConfig, &secretIDData)
	if err != nil {
		return nil, fmt.Errorf("error decoding secretID config from struct: %v", err)
	}

	// Get SecretID
	secretId, err := client.Logical().Write(rolePath+"/secret-id", secretIDData)
	if err != nil {
		return nil, fmt.Errorf("error reading approle secret_id: %v", err)
	}

	return &approle_auth{
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		roleID:     roleSecret.Data["role_id"].(string),
		role:       config.RoleConfig.Name,
		secretID:   secretId.Data["secret_id"].(string),
	}, nil
}
