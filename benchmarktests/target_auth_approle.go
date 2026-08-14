// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	ApproleAuthTestType   = "approle_auth"
	ApproleAuthTestMethod = "POST"
)

func init() {
	TestList[ApproleAuthTestType] = func() BenchmarkBuilder { return &ApproleAuth{} }
}

type ApproleAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	config     *ApproleAuthConfig
	logger     hclog.Logger
}

type ApproleAuthConfig struct {
	RoleConfig     *RoleConfig     `hcl:"role,block"`
	SecretIDConfig *SecretIDConfig `hcl:"secret_id,block"`
}

type RoleConfig struct {
	Name                 string   `hcl:"role_name,optional"`
	BindSecretID         *bool    `hcl:"bind_secret_id,optional"`
	SecretIDBoundCIDRS   []string `hcl:"secret_id_bound_cidrs,optional"`
	SecretIDNumUses      int      `hcl:"secret_id_num_uses,optional"`
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

type SecretIDConfig struct {
	Metadata        string   `hcl:"metadata,optional"`
	CIDRList        []string `hcl:"cidr_list,optional"`
	NumUses         int      `hcl:"num_uses,optional"`
	TTL             string   `hcl:"ttl,optional"`
	TokenBoundCIDRs []string `hcl:"token_bound_cidrs,optional"`
}

func (a *ApproleAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *ApproleAuthConfig `hcl:"config,block"`
	}{
		Config: &ApproleAuthConfig{
			RoleConfig: &RoleConfig{
				Name: "benchmark-role",
			},
			SecretIDConfig: &SecretIDConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	a.config = testConfig.Config
	return nil
}

func (a *ApproleAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	a.logger = targetLogger.Named(ApproleAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	a.logger.Trace(mountLogMessage("auth", "approle", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling approle auth: %v", err)
	}
	setupLogger := a.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("role"))
	rolePath := filepath.Join("auth", authPath, "role", a.config.RoleConfig.Name)
	if err := writeStruct(client, rolePath, a.config.RoleConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace("getting role-id")
	roleIDSecret, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return nil, fmt.Errorf("error reading approle role-id: %v", err)
	}

	setupLogger.Trace(parsingConfigLogMessage("secret-id"))
	secretIDData, err := structToMap(a.config.SecretIDConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing secret-id config from struct: %v", err)
	}

	setupLogger.Trace("getting secret-id")
	secretId, err := client.Logical().Write(rolePath+"/secret-id", secretIDData)
	if err != nil {
		return nil, fmt.Errorf("error reading approle secret-id: %v", err)
	}

	roleID := roleIDSecret.Data["role_id"].(string)
	secretID := secretId.Data["secret_id"].(string)

	return &ApproleAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		body:       fmt.Appendf(nil, `{"role_id": "%s", "secret_id": "%s"}`, roleID, secretID),
		logger:     a.logger,
	}, nil
}

func (a *ApproleAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: ApproleAuthTestMethod,
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   a.body,
	}
}

func (a *ApproleAuth) Cleanup(client *api.Client) error {
	return cleanupMount(a.logger, client, a.pathPrefix)
}

func (a *ApproleAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     ApproleAuthTestMethod,
		pathPrefix: a.pathPrefix,
	}
}

func (a *ApproleAuth) Flags(fs *flag.FlagSet) {}
