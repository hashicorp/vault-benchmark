// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	KubernetesSecretTestType          = "kubernetes_secret"
	KubernetesSecretTestMethod        = "POST"
	KubernetesServiceAccountJWTEnvVar = VaultBenchmarkEnvVarPrefix + "KUBERNETES_SERVICE_ACCOUNT_JWT"
	KubernetesCACertEnvVar            = VaultBenchmarkEnvVarPrefix + "KUBERNETES_CA_CERT"
)

func init() {
	TestList[KubernetesSecretTestType] = func() BenchmarkBuilder { return &KubernetesSecret{} }
}

type KubernetesSecret struct {
	pathPrefix string
	header     http.Header
	body       []byte
	roleName   string
	config     *KubernetesSecretConfig
	logger     hclog.Logger
}

type KubernetesSecretConfig struct {
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

func (k *KubernetesSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *KubernetesSecretConfig `hcl:"config,block"`
	}{
		Config: &KubernetesSecretConfig{
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

func (k *KubernetesSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := k.config
	k.logger = targetLogger.Named(KubernetesSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	k.logger.Trace(mountLogMessage("secrets", "kubernetes", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "kubernetes",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting kubernetes: %v", err)
	}

	setupLogger := k.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("kubernetes"))
	if err := writeStruct(client, secretPath+"/config", config.KubernetesConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, secretPath+"/roles/"+config.KubernetesRoleConfig.Name, config.KubernetesRoleConfig); err != nil {
		return nil, err
	}

	// Default namespace to a randomly selected allowed namespace or "default"
	namespace := "default"
	if len(config.KubernetesRoleConfig.AllowedKubernetesNamespaces) > 0 {
		allowedNS := config.KubernetesRoleConfig.AllowedKubernetesNamespaces
		// Otherwise randomly pick from the explicitly allowed namespaces
		if allowedNS[0] != "*" {
			namespace = allowedNS[rand.Intn(len(allowedNS))]
		}
	}

	requestBody := map[string]any{
		"kubernetes_namespace": namespace,
	}

	if config.KubernetesRoleConfig.TokenDefaultAudiences != "" {
		requestBody["audiences"] = config.KubernetesRoleConfig.TokenDefaultAudiences
	}

	if config.KubernetesRoleConfig.KubernetesRoleType == "ClusterRole" {
		requestBody["cluster_role_binding"] = true
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body: %v", err)
	}

	return &KubernetesSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.KubernetesRoleConfig.Name,
		body:       bodyBytes,
		logger:     k.logger,
	}, nil
}

func (k *KubernetesSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: KubernetesSecretTestMethod,
		URL:    client.Address() + k.pathPrefix + "/creds/" + k.roleName,
		Body:   k.body,
		Header: k.header,
	}
}

func (k *KubernetesSecret) Cleanup(client *api.Client) error {
	return cleanupMount(k.logger, client, k.pathPrefix)
}

func (k *KubernetesSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     KubernetesSecretTestMethod,
		pathPrefix: k.pathPrefix,
	}
}

func (k *KubernetesSecret) Flags(fs *flag.FlagSet) {}
