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
	LDAPStaticSecretTestType       = "ldap_static_secret"
	LDAPStaticSecretTestMethod     = "POST"
	LDAPStaticSecretBindPassEnvVar = VaultBenchmarkEnvVarPrefix + "LDAP_BIND_PASS"
)

func init() {
	TestList[LDAPStaticSecretTestType] = func() BenchmarkBuilder { return &LDAPStaticSecret{} }
}

type LDAPStaticSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *LDAPStaticSecretConfig
	logger     hclog.Logger
}

type LDAPStaticSecretConfig struct {
	LDAPStaticConfig     *LDAPStaticConfig     `hcl:"secret,block"`
	LDAPStaticRoleConfig *LDAPStaticRoleConfig `hcl:"role,block"`
}

type LDAPStaticConfig struct {
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

type LDAPStaticRoleConfig struct {
	Username       string `hcl:"username"`
	DN             string `hcl:"dn,optional"`
	RotationPeriod string `hcl:"rotation_period"`
}

func (r *LDAPStaticSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *LDAPStaticSecretConfig `hcl:"config,block"`
	}{
		Config: &LDAPStaticSecretConfig{
			LDAPStaticConfig: &LDAPStaticConfig{
				BindPass: os.Getenv(LDAPAuthBindPassEnvVar),
			},
			LDAPStaticRoleConfig: &LDAPStaticRoleConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	r.config = testConfig.Config

	if r.config.LDAPStaticConfig.BindPass == "" {
		return fmt.Errorf("no ldap bindpass provided but required")
	}

	return nil
}

func (r *LDAPStaticSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(LDAPStaticSecretTestType)

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
	if err := writeStruct(client, secretPath+"/config", r.config.LDAPStaticConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("ldap secret role"))
	if err := writeStruct(client, secretPath+"/static-role/"+r.config.LDAPStaticRoleConfig.Username, r.config.LDAPStaticRoleConfig); err != nil {
		return nil, err
	}

	return &LDAPStaticSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.LDAPStaticRoleConfig.Username,
		logger:     r.logger,
	}, nil
}

func (r *LDAPStaticSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: LDAPStaticSecretTestMethod,
		URL:    client.Address() + r.pathPrefix + "/rotate-role/" + r.roleName,
		Header: r.header,
	}
}

func (r *LDAPStaticSecret) Cleanup(client *api.Client) error {
	return cleanupMount(r.logger, client, r.pathPrefix)
}

func (r *LDAPStaticSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     LDAPStaticSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (m *LDAPStaticSecret) Flags(fs *flag.FlagSet) {}
