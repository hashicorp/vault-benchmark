package benchmarktests

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
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	ApproleAuthTestType   = "approle_auth"
	ApproleAuthTestMethod = "POST"
)

func init() {
	// "Register" this test to the main test registry
	TestList[ApproleAuthTestType] = func() BenchmarkBuilder { return &approle_auth{} }
}

// Approle Auth Test Struct
type approle_auth struct {
	pathPrefix string
	role       string
	roleID     string
	header     http.Header
	secretID   string
	config     *ApproleTestConfig
}

// Main Config Struct
type ApproleTestConfig struct {
	Config *ApproleAuthTestConfig `hcl:"config,block"`
}

// Intermediary struct to assist with HCL decoding
type ApproleAuthTestConfig struct {
	RoleConfig     *RoleConfig     `hcl:"role_config,block"`
	SecretIDConfig *SecretIDConfig `hcl:"secret_id_config,block"`
}

// AppRole Role Config
type RoleConfig struct {
	Name                 string   `hcl:"role_name"`
	BindSecretID         bool     `hcl:"bind_secret_id,optional"`
	SecretIDBoundCIDRS   []string `hcl:"secret_id_bound_cidrs,optional"`
	SecredIDNumUses      int      `hcl:"secret_id_num_uses,optional"`
	SecretIDTTL          string   `hcl:"secret_id_ttl,optional"`
	LocalSecretIDs       bool     `hcl:"local_secret_ids,optional"`
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

// AppRole SecretID Config
type SecretIDConfig struct {
	Metadata        string   `hcl:"metadata,optional"`
	CIDRList        []string `hcl:"cidr_list,optional"`
	NumUses         int      `hcl:"num_uses,optional"`
	TTL             string   `hcl:"ttl,optional"`
	TokenBoundCIDRs []string `hcl:"token_bound_cidrs,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (a *approle_auth) ParseConfig(body hcl.Body) {
	a.config = &ApproleTestConfig{
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
		Method: ApproleAuthTestMethod,
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
	tInfo := TargetInfo{
		method:     ApproleAuthTestMethod,
		pathPrefix: a.pathPrefix,
	}
	return tInfo
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
		return nil, fmt.Errorf("error enabling approle auth: %v", err)
	}

	// Decode RoleConfig struct into mapstructure to pass with request
	roleData, err := structToMap(config.RoleConfig)
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
	secretIDData, err := structToMap(config.SecretIDConfig)
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

func (l *approle_auth) Flags(fs *flag.FlagSet) {}
