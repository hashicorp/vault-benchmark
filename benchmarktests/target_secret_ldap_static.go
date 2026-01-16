// Copyright IBM Corp. 2022, 2025
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
	LDAPStaticSecretTestType       = "ldap_static_secret"
	LDAPStaticSecretTestMethod     = "POST"
	LDAPStaticSecretBindPassEnvVar = VaultBenchmarkEnvVarPrefix + "LDAP_BIND_PASS"
)

func init() {
	// "Register" this test to the main test registry
	TestList[LDAPStaticSecretTestType] = func() BenchmarkBuilder { return &LDAPStaticSecretTest{action: "rotate"} }
}

type LDAPStaticSecretTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *LDAPStaticSecretTestConfig
	logger     hclog.Logger
	action     string
}

// Main Config Struct
type LDAPStaticSecretTestConfig struct {
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

func (r *LDAPStaticSecretTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *LDAPStaticSecretTestConfig `hcl:"config,block"`
	}{
		Config: &LDAPStaticSecretTestConfig{
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

func (r *LDAPStaticSecretTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: LDAPStaticSecretTestMethod,
		URL:    client.Address() + r.pathPrefix + "/rotate-role/" + r.roleName,
		Header: r.header,
	}
}

func (r *LDAPStaticSecretTest) Cleanup(client *api.Client) error {
	r.logger.Trace(cleanupLogMessage(r.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (r *LDAPStaticSecretTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     LDAPStaticSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *LDAPStaticSecretTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(LDAPStaticSecretTestType)

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
	connectionConfigData, err := structToMap(r.config.LDAPStaticConfig)
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
	roleConfigData, err := structToMap(r.config.LDAPStaticRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("ldap secret role"), "name", r.config.LDAPStaticRoleConfig.Username)
	_, err = client.Logical().Write(secretPath+"/static-role/"+r.config.LDAPStaticRoleConfig.Username, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing ldap secret static role: %v", err)
	}

	return &LDAPStaticSecretTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.LDAPStaticRoleConfig.Username,
		logger:     r.logger,
	}, nil
}

func (m *LDAPStaticSecretTest) Flags(fs *flag.FlagSet) {}
