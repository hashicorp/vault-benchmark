// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
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
	KMIPSecretTestType   = "kmip_secret"
	KMIPSecretTestMethod = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[KMIPSecretTestType] = func() BenchmarkBuilder { return &KMIPTest{} }
}

type KMIPTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	scopeName  string
	config     *KMIPSecretTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type KMIPSecretTestConfig struct {
	KMIPConnectionConfig *KMIPConnectionConfig `hcl:"kmip,block"`
	KMIPRoleConfig       *KMIPRoleConfig       `hcl:"role,block"`
}

type KMIPConnectionConfig struct {
	ListenAddrs             string `hcl:"listen_addrs,optional"`
	ConnectionTimeout       string `hcl:"connection_timeout,optional"`
	ServerHostnames         string `hcl:"server_hostnames,optional"`
	SeverIPs                string `hcl:"server_ips,optional"`
	TLSCAKeyType            string `hcl:"tls_ca_key_type,optional"`
	TLSCAKeyBits            string `hcl:"tls_ca_key_bits,optional"`
	TLSMinVersion           string `hcl:"tls_min_version,optional"`
	DefaultTLSClientKeyType string `hcl:"default_tls_client_key_type,optional"`
	DefaultTLSClientKeyBits string `hcl:"default_tls_client_key_bits,optional"`
	DefaultTLSClientTTL     string `hcl:"default_tls_client_ttl,optional"`
}

type KMIPRoleConfig struct {
	Scope                     string `hcl:"scope,optional"`
	Role                      string `hcl:"role,optional"`
	TLSClientKeyType          string `hcl:"tls_client_key_type,optional"`
	TLSClientKeyBits          string `hcl:"tls_client_key_bits,optional"`
	TLSClientKeyTTL           string `hcl:"tls_client_key_ttl,optional"`
	OperationNone             string `hcl:"operation_none,optional"`
	OperationAll              string `hcl:"operation_all,optional"`
	OperationActive           string `hcl:"operation_active,optional"`
	OperationAddAttribute     string `hcl:"operation_add_attribute,optional"`
	OperationCreate           string `hcl:"operation_create,optional"`
	OperationDecrypt          string `hcl:"operation_decrypt,optional"`
	OperationDestroy          string `hcl:"operation_destroy,optional"`
	OperationDiscoverVersions string `hcl:"operation_discover_versions,optional"`
	OperationEncrypt          string `hcl:"operation_encrypt,optional"`
	OperationGet              string `hcl:"operation_get,optional"`
	OperationGetAttributeList string `hcl:"operation_get_attribute_list,optional"`
	OperationGetAttributes    string `hcl:"operation_get_attributes,optional"`
	OperationImport           string `hcl:"operation_import,optional"`
	OperationLocate           string `hcl:"operation_locate,optional"`
	OperationQuery            string `hcl:"operation_query,optional"`
	OperationRegister         string `hcl:"operation_register,optional"`
	OperationRekey            string `hcl:"operation_rekey,optional"`
	OperationRevoke           string `hcl:"operation_revoke,optional"`
}

func (k *KMIPTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *KMIPSecretTestConfig `hcl:"config,block"`
	}{
		Config: &KMIPSecretTestConfig{
			KMIPConnectionConfig: &KMIPConnectionConfig{},
			KMIPRoleConfig: &KMIPRoleConfig{
				Scope: "benchmark-scope",
				Role:  "benchmark-role",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	k.config = testConfig.Config

	return nil
}

func (k *KMIPTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: KMIPSecretTestMethod,
		URL:    client.Address() + k.pathPrefix + "/scope/" + k.scopeName + "/role/" + k.roleName,
		Header: k.header,
	}
}

func (k *KMIPTest) Cleanup(client *api.Client) error {
	k.logger.Trace(cleanupLogMessage(k.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(k.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (k *KMIPTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     KMIPSecretTestMethod,
		pathPrefix: k.pathPrefix,
	}
}

func (k *KMIPTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	k.logger = targetLogger.Named(KMIPSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	k.logger.Trace(mountLogMessage("secrets", "kmip", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "kmip",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting kmip secrets engine: %v", err)
	}

	setupLogger := k.logger.Named(secretPath)

	// Decode KMIP Config
	setupLogger.Trace(parsingConfigLogMessage("kmip connection"))
	connectionConfigData, err := structToMap(k.config.KMIPConnectionConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing kmip connection config from struct: %v", err)
	}

	// Write connection config
	setupLogger.Trace(writingLogMessage("kmip connection config"))
	_, err = client.Logical().Write(secretPath+"/config", connectionConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing kmip config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleConfigData, err := structToMap(k.config.KMIPRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Scope
	setupLogger.Trace(writingLogMessage("kmip scope"), "scope", k.config.KMIPRoleConfig.Scope)
	_, err = client.Logical().Write(secretPath+"/scope/"+k.config.KMIPRoleConfig.Scope, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing kmip scope: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("kmip role"), "name", k.config.KMIPRoleConfig.Role)
	_, err = client.Logical().Write(secretPath+"/scope/"+k.config.KMIPRoleConfig.Scope+"/role/"+k.config.KMIPRoleConfig.Role, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing kmip role: %v", err)
	}

	return &KMIPTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   k.config.KMIPRoleConfig.Role,
		scopeName:  k.config.KMIPRoleConfig.Scope,
		logger:     k.logger,
	}, nil
}

func (k *KMIPTest) Flags(fs *flag.FlagSet) {}
