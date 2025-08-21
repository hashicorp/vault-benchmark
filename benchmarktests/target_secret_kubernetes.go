// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
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
	KubernetesSecretTestType          = "kubernetes_secret"
	KubernetesSecretTestMethod        = "POST"
	KubernetesServiceAccountJWTEnvVar = VaultBenchmarkEnvVarPrefix + "KUBERNETES_SERVICE_ACCOUNT_JWT"
	KubernetesCACertEnvVar            = VaultBenchmarkEnvVarPrefix + "KUBERNETES_CA_CERT"
)

func init() {
	// "Register" this test to the main test registry
	TestList[KubernetesSecretTestType] = func() BenchmarkBuilder { return &KubernetesTest{} }
}

type KubernetesTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	body       []byte
	config     *KubernetesSecretTestConfig
	logger     hclog.Logger
}

type KubernetesSecretTestConfig struct {
	KubernetesConfig     *KubernetesConfig     `hcl:"kubernetes,block"`
	KubernetesRoleConfig *KubernetesRoleConfig `hcl:"role,block"`
}

type KubernetesConfig struct {
	KubernetesHost    string `hcl:"kubernetes_host,optional"`
	KubernetesCACert  string `hcl:"kubernetes_ca_cert,optional"`
	ServiceAccountJWT string `hcl:"service_account_jwt,optional"`
	DisableLocalCAJWT bool   `hcl:"disable_local_ca_jwt,optional"`
}

type KubernetesRoleConfig struct {
	Name                               string            `hcl:"name,optional"`
	AllowedKubernetesNamespaces        []string          `hcl:"allowed_kubernetes_namespaces,optional"`
	AllowedKubernetesNamespaceSelector string            `hcl:"allowed_kubernetes_namespace_selector,optional"`
	TokenMaxTTL                        string            `hcl:"token_max_ttl,optional"`
	TokenDefaultTTL                    string            `hcl:"token_default_ttl,optional"`
	TokenDefaultAudiences              string            `hcl:"token_default_audiences,optional"`
	ServiceAccountName                 string            `hcl:"service_account_name,optional"`
	KubernetesRoleName                 string            `hcl:"kubernetes_role_name,optional"`
	KubernetesRoleType                 string            `hcl:"kubernetes_role_type,optional"`
	KubernetesRoleRefType              string            `hcl:"kubernetes_role_ref_type,optional"`
	GeneratedRoleRules                 string            `hcl:"generated_role_rules,optional"`
	NameTemplate                       string            `hcl:"name_template,optional"`
	ExtraAnnotations                   map[string]string `hcl:"extra_annotations,optional"`
	ExtraLabels                        map[string]string `hcl:"extra_labels,optional"`
}

func (k *KubernetesTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *KubernetesSecretTestConfig `hcl:"config,block"`
	}{
		Config: &KubernetesSecretTestConfig{
			KubernetesConfig: &KubernetesConfig{
				KubernetesHost:    "https://kubernetes.default.svc",
				ServiceAccountJWT: os.Getenv(KubernetesServiceAccountJWTEnvVar),
				KubernetesCACert:  os.Getenv(KubernetesCACertEnvVar),
				DisableLocalCAJWT: false,
			},
			KubernetesRoleConfig: &KubernetesRoleConfig{
				Name:                        "benchmark-role",
				AllowedKubernetesNamespaces: []string{"default"},
				KubernetesRoleType:          "Role",
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

func (k *KubernetesTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: KubernetesSecretTestMethod,
		URL:    client.Address() + k.pathPrefix + "/creds/" + k.roleName,
		Body:   k.body,
		Header: k.header,
	}
}

func (k *KubernetesTest) Cleanup(client *api.Client) error {
	k.logger.Trace(cleanupLogMessage(k.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(k.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (k *KubernetesTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     KubernetesSecretTestMethod,
		pathPrefix: k.pathPrefix,
	}
}

func (k *KubernetesTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := k.config
	k.logger = targetLogger.Named(KubernetesSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	k.logger.Trace(mountLogMessage("secrets", "kubernetes", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "kubernetes",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting kubernetes: %v", err)
	}

	setupLogger := k.logger.Named(secretPath)

	// Decode Kubernetes Config
	setupLogger.Trace(parsingConfigLogMessage("kubernetes"))
	kubernetesConfigData, err := structToMap(config.KubernetesConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing kubernetes config from struct: %v", err)
	}

	// Write Kubernetes config
	setupLogger.Trace(writingLogMessage("kubernetes config"))
	_, err = client.Logical().Write(secretPath+"/config", kubernetesConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing kubernetes config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	kubernetesRoleConfigData, err := structToMap(config.KubernetesRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("kubernetes role"), "name", config.KubernetesRoleConfig.Name)
	_, err = client.Logical().Write(secretPath+"/roles/"+config.KubernetesRoleConfig.Name, kubernetesRoleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing kubernetes role: %v", err)
	}

	// Prepare request body for credential generation
	// Default namespace to the first allowed namespace or "default"
	namespace := "default"
	if len(config.KubernetesRoleConfig.AllowedKubernetesNamespaces) > 0 {
		// If "*" is allowed, use "default", otherwise use the first allowed namespace
		if config.KubernetesRoleConfig.AllowedKubernetesNamespaces[0] != "*" {
			namespace = config.KubernetesRoleConfig.AllowedKubernetesNamespaces[0]
		}
	}

	// Build request body for credential generation
	requestBody := map[string]interface{}{
		"kubernetes_namespace": namespace,
	}

	// Add optional TTL if specified
	if config.KubernetesRoleConfig.TokenDefaultTTL != "" {
		requestBody["ttl"] = config.KubernetesRoleConfig.TokenDefaultTTL
	}

	// Add optional audiences if specified
	if config.KubernetesRoleConfig.TokenDefaultAudiences != "" {
		requestBody["audiences"] = config.KubernetesRoleConfig.TokenDefaultAudiences
	}

	// For ClusterRole types, set cluster_role_binding to true
	if config.KubernetesRoleConfig.KubernetesRoleType == "ClusterRole" {
		requestBody["cluster_role_binding"] = true
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body: %v", err)
	}

	return &KubernetesTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.KubernetesRoleConfig.Name,
		body:       bodyBytes,
		logger:     k.logger,
	}, nil
}

func (k *KubernetesTest) Flags(fs *flag.FlagSet) {}
