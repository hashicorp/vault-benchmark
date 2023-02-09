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
	Name                 string   `hcl:"role_name" json:"role_name"`
	BindSecretID         bool     `hcl:"bind_secret_id,optional" json:"bind_secret_id"`
	SecretIDBoundCIDRS   []string `hcl:"secret_id_bound_cidrs,optional" json:"secret_id_bound_cidrs"`
	SecredIDNumUses      int      `hcl:"secret_id_num_uses,optional" json:"secret_id_num_uses"`
	SecretIDTTL          string   `hcl:"secret_id_ttl,optional" json:"secret_id_ttl"`
	LocalSecretIDs       bool     `hcl:"local_secret_ids,optional" json:"local_secret_ids"`
	TokenTTL             string   `hcl:"token_ttl,optional" json:"token_ttl"`
	TokenMaxTTL          string   `hcl:"token_max_ttl,optional" json:"token_max_ttl"`
	TokenPolicies        []string `hcl:"token_policies,optional" json:"token_policies"`
	Policies             []string `hcl:"policies,optional" json:"policies"`
	TokenBoundCIDRs      []string `hcl:"token_bound_cidrs,optional" json:"token_bound_cidrs"`
	TokenExplicitMaxTTL  string   `hcl:"token_explicit_max_ttl,optional" json:"token_explicit_max_ttl"`
	TokenNoDefaultPolicy bool     `hcl:"token_no_default_policy,optional" json:"token_no_default_policy"`
	TokenNumUses         int      `hcl:"token_num_uses,optional" json:"token_num_uses"`
	TokenPeriod          string   `hcl:"token_period,optional" json:"token_period"`
	TokenType            string   `hcl:"token_type,optional" json:"token_type"`
}

// AppRole SecretID Config
type SecretIDConfig struct {
	Metadata        string   `hcl:"metadata,optional" json:"metadata"`
	CIDRList        []string `hcl:"cidr_list,optional" json:"cidr_list"`
	NumUses         int      `hcl:"num_uses,optional" json:"num_uses"`
	TTL             string   `hcl:"ttl,optional" json:"ttl"`
	TokenBoundCIDRs []string `hcl:"token_bound_cidrs,optional" json:"token_bound_cidrs"`
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

	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling approle: %v", err)
	}

	roleData := make(map[string]interface{})
	err = mapstructure.Decode(config.RoleConfig, &roleData)
	if err != nil {
		return nil, fmt.Errorf("error decoding role config from struct: %v", err)
	}

	rolePath := filepath.Join("auth", authPath, "role", config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error creating approle role %q: %v", config.RoleConfig.Name, err)
	}

	secretRole, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return nil, fmt.Errorf("error reading approle role_id: %v", err)
	}

	secretData := make(map[string]interface{})
	err = mapstructure.Decode(config.SecretIDConfig, &secretData)
	if err != nil {
		return nil, fmt.Errorf("error decoding secretID config from struct: %v", err)
	}

	secretId, err := client.Logical().Write(rolePath+"/secret-id", secretData)
	if err != nil {
		return nil, fmt.Errorf("error reading approle secret_id: %v", err)
	}

	return &approle_auth{
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		roleID:     secretRole.Data["role_id"].(string),
		role:       config.RoleConfig.Name,
		secretID:   secretId.Data["secret_id"].(string),
	}, nil
}
