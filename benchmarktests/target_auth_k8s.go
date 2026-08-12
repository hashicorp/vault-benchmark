// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	KubeAuthTestType               = "kube_auth"
	KubeAuthTestMethod             = "POST"
	DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func init() {
	TestList[KubeAuthTestType] = func() BenchmarkBuilder { return &KubernetesAuth{} }
}

type KubernetesAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	config     *KubernetesAuthConfig
	logger     hclog.Logger
}

type KubernetesAuthConfig struct {
	KubernetesAuthMountConfig     *KubernetesAuthMountConfig     `hcl:"auth,block"`
	KubernetesAuthRoleConfig *KubernetesAuthRoleConfig `hcl:"role,block"`
}

type KubernetesAuthMountConfig struct {
	KubernetesHost    string   `hcl:"kubernetes_host"`
	KubernetesCACert  string   `hcl:"kubernetes_ca_cert,optional"`
	TokenReviewerJWT  string   `hcl:"token_reviewer_jwt,optional"`
	PEMKeys           []string `hcl:"pem_keys,optional"`
	DisableLocalCAJWT bool     `hcl:"disable_local_ca_jwt,optional"`

	// Deprecated Parameters (Including for older versions of Vault)
	DisableISSValidation bool   `hcl:"disable_iss_validation,optional"`
	Issuer               string `hcl:"issuer,optional"`
}

type KubernetesAuthRoleConfig struct {
	Name                          string   `hcl:"name"`
	BoundServiceAccountNames      []string `hcl:"bound_service_account_names"`
	BoundServiceAccountNamespaces []string `hcl:"bound_service_account_namespaces"`
	Audience                      string   `hcl:"audience,optional"`
	AliasNameSource               string   `hcl:"alias_name_source,optional"`
	TokenTTL                      string   `hcl:"token_ttl,optional"`
	TokenMaxTTL                   string   `hcl:"token_max_ttl,optional"`
	TokenPolicies                 []string `hcl:"token_policies,optional"`
	TokenBoundCIDRs               []string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL           string   `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy          bool     `hcl:"token_no_default_policy,optional"`
	TokenNumUses                  int      `hcl:"token_num_uses,optional"`
	TokenPeriod                   string   `hcl:"token_period,optional"`
	TokenType                     string   `hcl:"token_type,optional"`
}

func (k *KubernetesAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *KubernetesAuthConfig `hcl:"config,block"`
	}{
		Config: &KubernetesAuthConfig{
			KubernetesAuthMountConfig:     &KubernetesAuthMountConfig{},
			KubernetesAuthRoleConfig: &KubernetesAuthRoleConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	k.config = testConfig.Config
	return nil
}

func (k *KubernetesAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	k.logger = targetLogger.Named(KubeAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	k.logger.Trace(mountLogMessage("auth", "kubernetes", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "kubernetes",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling kubernetes: %v", err)
	}
	setupLogger := k.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("kubernetes auth"))
	if err := writeStruct(client, "auth/"+authPath+"/config", k.config.KubernetesAuthMountConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, "auth/"+authPath+"/role/"+k.config.KubernetesAuthRoleConfig.Name, k.config.KubernetesAuthRoleConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace("reading default service account token from file")
	jwt, err := readTokenFromFile(DefaultServiceAccountTokenPath)
	if err != nil {
		return nil, err
	}

	return &KubernetesAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		// TODO: service account tokens rotate (~1h); long benchmarks accumulate 401s. Apply cachedBody refresh, re-reading DefaultServiceAccountTokenPath.
		body:       fmt.Appendf(nil, `{"role": "%s", "jwt": "%s"}`, k.config.KubernetesAuthRoleConfig.Name, jwt),
		logger:     k.logger,
	}, nil
}

func (k *KubernetesAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: KubeAuthTestMethod,
		URL:    client.Address() + k.pathPrefix + "/login",
		Header: k.header,
		Body:   k.body,
	}
}

func (k *KubernetesAuth) Cleanup(client *api.Client) error {
	return cleanupMount(k.logger, client, k.pathPrefix)
}

func (k *KubernetesAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     KubeAuthTestMethod,
		pathPrefix: k.pathPrefix,
	}
}

func (k *KubernetesAuth) Flags(fs *flag.FlagSet) {}

func readTokenFromFile(filepath string) (string, error) {
	jwt, err := os.ReadFile(filepath)
	if err != nil {
		return "", fmt.Errorf("unable to read file containing service account token: %w", err)
	}
	return string(jwt), nil
}
