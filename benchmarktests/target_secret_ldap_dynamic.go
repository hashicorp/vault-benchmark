// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	LDAPDynamicSecretTestType   = "ldap_dynamic_secret"
	LDAPDynamicSecretTestMethod = "GET"
	LDAPSecretBindPassEnvVar    = VaultBenchmarkEnvVarPrefix + "LDAP_BIND_PASS"
)

func init() {
	// "Register" this test to the main test registry
	TestList[LDAPDynamicSecretTestType] = func() BenchmarkBuilder { return &LDAPDynamicSecretTest{} }
}

type LDAPDynamicSecretTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *LDAPDynamicSecretTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type LDAPDynamicSecretTestConfig struct {
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

func (r *LDAPDynamicSecretTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *LDAPDynamicSecretTestConfig `hcl:"config,block"`
	}{
		Config: &LDAPDynamicSecretTestConfig{
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

func (r *LDAPDynamicSecretTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: LDAPDynamicSecretTestMethod,
		URL:    client.Address() + r.pathPrefix + "/creds/" + r.roleName,
		Header: r.header,
	}
}

func (r *LDAPDynamicSecretTest) Cleanup(client *api.Client) error {
	r.logger.Trace(cleanupLogMessage(r.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (r *LDAPDynamicSecretTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     LDAPDynamicSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *LDAPDynamicSecretTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(LDAPDynamicSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	r.logger.Trace(mountLogMessage("secrets", "ldap", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "ldap",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting ldap secrets engine: %v", err)
	}

	setupLogger := r.logger.Named(secretPath)

	// Decode LDAP Connection Config
	setupLogger.Trace(parsingConfigLogMessage("ldap secret"))
	connectionConfigData, err := structToMap(r.config.LDAPDynamicConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing ldap secret config from struct: %v", err)
	}

	// Write connection config
	setupLogger.Trace(writingLogMessage("ldap secret config"))
	_, err = client.Logical().Write(secretPath+"/config", connectionConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing ldap secret config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("ldap secret role"))
	roleConfigData, err := structToMap(r.config.LDAPDynamicRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("ldap secret role"), "name", r.config.LDAPDynamicRoleConfig.RoleName)
	_, err = client.Logical().Write(secretPath+"/role/"+r.config.LDAPDynamicRoleConfig.RoleName, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing ldap secret role: %v", err)
	}

	return &LDAPDynamicSecretTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.LDAPDynamicRoleConfig.RoleName,
		logger:     r.logger,
	}, nil
}

func (m *LDAPDynamicSecretTest) Flags(fs *flag.FlagSet) {}
