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
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Flags
var PctApproleLogin = flag.Int("pct_approle_login", 0, "percent of requests that are approle logins")

func init() {
	// Add to test list
	TestList["approle_auth"] = func() BenchmarkTarget { return &approle_auth{} }
}

type approle_auth struct {
	pathPrefix string
	role       string
	roleID     string
	header     http.Header
	secretID   string
}

type ApproleAuthTestConfig struct {
	RoleConfig     *RoleConfig     `hcl:"role_config,block"`
	SecretIDConfig *SecretIDConfig `hcl:"secret_id_config,block"`
}

type RoleConfig struct {
	Name                 *string   `hcl:"role_name" json:"role_name"`
	BindSecretID         *bool     `hcl:"bind_secret_id" json:"bind_secret_id"`
	SecretIDBoundCIDRS   *[]string `hcl:"secret_id_bound_cidrs" json:"secret_id_bound_cidrs"`
	SecredIDNumUses      *int      `hcl:"secret_id_num_uses" json:"secret_id_num_uses"`
	SecretIDTTL          *string   `hcl:"secret_id_ttl" json:"secret_id_ttl"`
	LocalSecretIDs       *bool     `hcl:"local_secret_ids" json:"local_secret_ids"`
	TokenTTL             *string   `hcl:"token_ttl" json:"token_ttl"`
	TokenMaxTTL          *string   `hcl:"token_max_ttl" json:"token_max_ttl"`
	TokenPolicies        *[]string `hcl:"token_policies" json:"token_policies"`
	Policies             *[]string `hcl:"policies" json:"policies"`
	TokenBoundCIDRs      *[]string `hcl:"token_bound_cidrs" json:"token_bound_cidrs"`
	TokenExplicitMaxTTL  *string   `hcl:"token_explicit_max_ttl" json:"token_explicit_max_ttl"`
	TokenNoDefaultPolicy *bool     `hcl:"token_no_default_policy" json:"token_no_default_policy"`
	TokenNumUses         *int      `hcl:"token_num_uses" json:"token_num_uses"`
	TokenPeriod          *string   `hcl:"token_period" json:"token_period"`
	TokenType            *string   `hcl:"token_type" json:"token_type"`
}

type SecretIDConfig struct {
	Metadata        *string   `hcl:"metadata" json:"metadata"`
	CIDRList        *[]string `hcl:"cidr_list" json:"cidr_list"`
	NumUses         *int      `hcl:"num_uses" json:"num_uses"`
	TTL             *string   `hcl:"ttl" json:"ttl"`
	TokenBoundCIDRs *[]string `hcl:"token_bound_cidrs" json:"token_bound_cidrs"`
}

func (a *approle_auth) ParseConfig(body hcl.Body) interface{} {
	conf := &ApproleAuthTestConfig{}
	diags := gohcl.DecodeBody(body, nil, conf)
	if diags.HasErrors() {
		fmt.Println(diags)
	}
	return conf
}

func (a *approle_auth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   []byte(fmt.Sprintf(`{"role_id": "%s", "secret_id": "%s"}`, a.roleID, a.secretID)),
	}
}

func (a *approle_auth) createTargetFraction() targetFraction {
	return targetFraction{
		pathPrefix: a.pathPrefix,
		method:     "POST",
	}
}

func (a *approle_auth) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(a.pathPrefix, "/v1/", "/sys/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (a *approle_auth) Setup(client *api.Client, randomMountName bool, test_config interface{}) (BenchmarkTarget, error) {
	config := test_config.(ApproleAuthTestConfig)
	authPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMountName {
		authPath = "approle"
	}

	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling approle: %v", err)
	}

	rolePath := filepath.Join("auth", authPath, "role", *config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"token_ttl":      config.RoleConfig.TokenTTL,
		"token_max_ttl":  config.RoleConfig.TokenMaxTTL,
		"secret_id_ttl":  config.RoleConfig.SecretIDTTL,
		"token_policies": config.RoleConfig.TokenPolicies,
		"token_type":     config.RoleConfig.TokenType,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating approle role %q: %v", config.RoleConfig.Name, err)
	}

	secretRole, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return nil, fmt.Errorf("error reading approle role_id: %v", err)
	}

	secretId, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		return nil, fmt.Errorf("error reading approle secret_id: %v", err)
	}

	return &approle_auth{
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		roleID:     secretRole.Data["role_id"].(string),
		role:       *config.RoleConfig.Name,
		secretID:   secretId.Data["secret_id"].(string),
	}, nil
}
