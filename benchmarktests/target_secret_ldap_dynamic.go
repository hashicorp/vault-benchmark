// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	LDAPDynamicSecretTestType   = "ldap_dynamic_secret"
	LDAPDynamicSecretTestMethod = "GET"
	LDAPSecretBindPassEnvVar    = VaultBenchmarkEnvVarPrefix + "LDAP_BIND_PASS"
)

func init() {
	TestList[LDAPDynamicSecretTestType] = func() BenchmarkBuilder { return &LDAPDynamicSecret{} }
}

type LDAPDynamicSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *LDAPDynamicSecretConfig
	logger     hclog.Logger
}

type LDAPDynamicSecretConfig struct {
	LDAPDynamicConfig     *LDAPDynamicConfig     `hcl:"secret,block"`
	LDAPDynamicRoleConfig *LDAPDynamicRoleConfig `hcl:"role,block"`
}

type LDAPDynamicConfig struct {
	BindDN            string `hcl:"binddn"`
	BindPass          string `hcl:"bindpass,optional"`
	URL               string `hcl:"url,optional"`
	PasswordPolicy    string `hcl:"password_policy,optional"`
	Schema            string `hcl:"schema,optional"`
	UserDN            string `hcl:"userdn,optional"`
	UserAttr          string `hcl:"userattr,optional"`
	UPNDomain         string `hcl:"upndomain,optional"`
	ConnectionTimeout int    `hcl:"connection_timeout,optional"`
	RequestTimeout    int    `hcl:"request_timeout,optional"`
	StartTLS          bool   `hcl:"starttls,optional"`
	InsecureTLS       bool   `hcl:"insecure_tls,optional"`
	Certificate       string `hcl:"certificate,optional"`
	ClientTLSCert     string `hcl:"client_tls_cert,optional"`
	ClientTLSKey      string `hcl:"client_tls_key,optional"`
}

type LDAPDynamicRoleConfig struct {
	RoleName         string `hcl:"role_name,optional"`
	CreationLDIF     string `hcl:"creation_ldif"`
	DeletionLDIF     string `hcl:"deletion_ldif"`
	RollbackLDIF     string `hcl:"rollback_ldif,optional"`
	UsernameTemplate string `hcl:"username_template,optional"`
	DefaultTTL       int    `hcl:"default_ttl,optional"`
	MaxTTL           int    `hcl:"max_ttl,optional"`
}

func (r *LDAPDynamicSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *LDAPDynamicSecretConfig `hcl:"config,block"`
	}{
		Config: &LDAPDynamicSecretConfig{
			LDAPDynamicConfig: &LDAPDynamicConfig{
				BindPass: os.Getenv(LDAPAuthBindPassEnvVar),
			},
			LDAPDynamicRoleConfig: &LDAPDynamicRoleConfig{
				RoleName: "benchmark-role",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	r.config = testConfig.Config

	if r.config.LDAPDynamicConfig.BindPass == "" {
		return fmt.Errorf("no ldap bindpass provided but required")
	}

	return nil
}

func (r *LDAPDynamicSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(LDAPDynamicSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	r.logger.Trace(mountLogMessage("secrets", "ldap", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "ldap",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting ldap secrets engine: %v", err)
	}

	setupLogger := r.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("ldap secret"))
	if err := writeStruct(client, secretPath+"/config", r.config.LDAPDynamicConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("ldap secret role"))
	if err := writeStruct(client, secretPath+"/role/"+r.config.LDAPDynamicRoleConfig.RoleName, r.config.LDAPDynamicRoleConfig); err != nil {
		return nil, err
	}

	return &LDAPDynamicSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.LDAPDynamicRoleConfig.RoleName,
		logger:     r.logger,
	}, nil
}

func (r *LDAPDynamicSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: LDAPDynamicSecretTestMethod,
		URL:    client.Address() + r.pathPrefix + "/creds/" + r.roleName,
		Header: r.header,
	}
}

func (r *LDAPDynamicSecret) Cleanup(client *api.Client) error {
	return cleanupMount(r.logger, client, r.pathPrefix)
}

func (r *LDAPDynamicSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     LDAPDynamicSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (m *LDAPDynamicSecret) Flags(fs *flag.FlagSet) {}
