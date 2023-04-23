package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	KubeAuthTestType               = "kube_auth"
	KubeAuthTestMethod             = "POST"
	DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func init() {
	// "Register" this test to the main test registry
	TestList[KubeAuthTestType] = func() BenchmarkBuilder { return &KubeAuth{} }
}

type KubeAuth struct {
	pathPrefix string
	roleName   string
	jwt        string
	header     http.Header
	timeout    time.Duration
	config     *KubeTestConfig
	logger     hclog.Logger
}

type KubeTestConfig struct {
	Config *KubeAuthTestConfig `hcl:"config,block"`
}

type KubeAuthTestConfig struct {
	KubeAuthConfig     *KubeAuthConfig     `hcl:"auth,block"`
	KubeTestRoleConfig *KubeTestRoleConfig `hcl:"role,block"`
}

type KubeAuthConfig struct {
	KubernetesHost    string   `hcl:"kubernetes_host"`
	KubernetesCACert  string   `hcl:"kubernetes_ca_cert,optional"`
	TokenReviewerJWT  string   `hcl:"token_reviewer_jwt,optional"`
	PEMKeys           []string `hcl:"pem_keys,optional"`
	DisableLocalCAJWT bool     `hcl:"disable_local_ca_jwt,optional"`

	// Deprecated Parameters (Including for older versions of Vault)
	DisableISSValidation bool   `hcl:"disable_iss_validation,optional"`
	Issuer               string `hcl:"issuer,optional"`
}

type KubeTestRoleConfig struct {
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

func (k *KubeAuth) ParseConfig(body hcl.Body) error {
	k.config = &KubeTestConfig{
		Config: &KubeAuthTestConfig{
			KubeAuthConfig:     &KubeAuthConfig{},
			KubeTestRoleConfig: &KubeTestRoleConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, k.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	return nil
}

func (k *KubeAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: KubeAuthTestMethod,
		URL:    client.Address() + k.pathPrefix + "/login",
		Header: k.header,
		Body:   []byte(fmt.Sprintf(`{"role": "%s", "jwt": "%s"}`, k.roleName, k.jwt)),
	}
}

func (k *KubeAuth) Cleanup(client *api.Client) error {
	k.logger.Trace(cleanupLogMessage(k.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(k.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (k *KubeAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     KubeAuthTestMethod,
		pathPrefix: k.pathPrefix,
	}
}

func readTokenFromFile(filepath string) (string, error) {
	jwt, err := os.ReadFile(filepath)
	if err != nil {
		return "", fmt.Errorf("unable to read file containing service account token: %w", err)
	}
	return string(jwt), nil
}

func (k *KubeAuth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	config := k.config.Config
	k.logger = targetLogger.Named(KubeAuthTestType)

	if randomMountName {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("can't generate UUID for mount name: %v", err)
		}
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
	kubeAuthConfig, err := structToMap(config.KubeAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing kubernetes auth config from struct: %v", err)
	}

	// Write Kubernetes config
	setupLogger.Trace(writingLogMessage("kubernetes auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config", kubeAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing Kubernetes config: %v", err)
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	kubeRoleConfig, err := structToMap(config.KubeTestRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Write Kubernetes Role
	setupLogger.Trace(writingLogMessage("role"), "name", config.KubeTestRoleConfig.Name)
	_, err = client.Logical().Write("auth/"+authPath+"/role/"+config.KubeTestRoleConfig.Name, kubeRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing Kubernetes role: %v", err)
	}

	// Load JWT
	setupLogger.Trace("reading default service account token from file")
	jwt, err := readTokenFromFile(DefaultServiceAccountTokenPath)
	if err != nil {
		return nil, err
	}

	return &KubeAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		roleName:   k.config.Config.KubeTestRoleConfig.Name,
		jwt:        jwt,
		timeout:    k.timeout,
		logger:     k.logger,
	}, nil
}

// Func Flags accepts a flag set to assign additional flags defined in the function
func (k *KubeAuth) Flags(fs *flag.FlagSet) {}
