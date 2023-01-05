package vegeta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type kubernetestest struct {
	pathPrefix string
	roleName   string
	jwt        string
	header     http.Header
}

type KubernetesAuthConfig struct {
	KubernetesHost    string   `json:"kubernetes_host"`
	KubernetesCACert  string   `json:"kubernetes_ca_cert"`
	TokenReviewerJWT  string   `json:"token_reviewer_jwt"`
	PEMKeys           []string `json:"pem_keys"`
	DisableLocalCAJWT bool     `json:"disable_local_ca_jwt"`

	// Deprecated Parameters (Including for older versions of Vault)
	DisableISSValidation bool   `json:"disable_iss_validation"`
	Issuer               string `json:"issuer"`
}

type KubernetesTestRoleConfig struct {
	Name                          string   `json:"name"`
	BoundServiceAccountNames      []string `json:"bound_service_account_names"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
	Audience                      string   `json:"audience"`
	AliasNameSource               string   `json:"alias_name_source"`
	TokenTTL                      string   `json:"token_ttl"`
	TokenMaxTTL                   string   `json:"token_max_ttl"`
	TokenPolicies                 []string `json:"token_policies"`
	TokenBoundCIDRs               []string `json:"token_bound_cidrs"`
	TokenExplicitMaxTTL           string   `json:"token_explicit_max_ttl"`
	TokenNoDefaultPolicy          bool     `json:"token_no_default_policy"`
	TokenNumUses                  int      `json:"token_num_uses"`
	TokenPeriod                   string   `json:"token_period"`
	TokenType                     string   `json:"token_type"`
}

const (
	defaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func (c *KubernetesAuthConfig) FromJSON(path string) error {
	// Set Defaults
	c.DisableISSValidation = true

	if path == "" {
		return fmt.Errorf("no Kubernetes Config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(c); err != nil {
		return err
	}

	// Check for required fields
	switch {
	case c.KubernetesHost == "":
		return fmt.Errorf("no Kubernetes host url provided but is required")
	default:
		return nil
	}
}

func (r *KubernetesTestRoleConfig) FromJSON(path string) error {
	// Set Defaults
	r.AliasNameSource = "serviceaccount_uid"

	if path == "" {
		return fmt.Errorf("no Kubernetes user config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(r); err != nil {
		return err
	}

	// Check for required fields
	switch {
	case len(r.BoundServiceAccountNames) == 0:
		return fmt.Errorf("no kubernetes service account names passed but are required")
	case len(r.BoundServiceAccountNamespaces) == 0:
		return fmt.Errorf("no kubernetes service account namespaces passed but are required")
	default:
		return nil
	}
}

func (k *kubernetestest) login(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + k.pathPrefix + "/login",
		Header: k.header,
		Body:   []byte(fmt.Sprintf(`{"role": "%s", "jwt": "%s"}`, k.roleName, k.jwt)),
	}
}

func (k *kubernetestest) cleanup(client *api.Client) error {
	client.SetClientTimeout(time.Second * 600)

	// Revoke all leases
	_, err := client.Logical().Write(strings.Replace(k.pathPrefix, "/v1/", "/sys/leases/revoke-prefix/", 1), map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("error cleaning up leases: %v", err)
	}

	_, err = client.Logical().Delete(strings.Replace(k.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupKubernetesAuth(client *api.Client, randomMounts bool, config *KubernetesAuthConfig, testRoleConfig *KubernetesTestRoleConfig) (*kubernetestest, error) {
	authPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		authPath = "kubernetes"
	}

	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "kubernetes",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling kubernetes: %v", err)
	}

	// Write Kubernetes config
	_, err = client.Logical().Write("auth/"+authPath+"/config", map[string]interface{}{
		"kubernetes_host":      config.KubernetesHost,
		"kubernetes_ca_cert":   config.KubernetesCACert,
		"token_reviewer_jwt":   config.TokenReviewerJWT,
		"pem_keys":             config.PEMKeys,
		"disable_local_ca_jwt": config.DisableLocalCAJWT,

		// Deprecated Parameters (Including for older version of Vault)
		"disable_iss_validation": config.DisableISSValidation,
		"issuer":                 config.Issuer,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing Kubernetes config: %v", err)
	}

	// Write Kubernetes Role
	_, err = client.Logical().Write("auth/"+authPath+"/role/"+testRoleConfig.Name, map[string]interface{}{
		"bound_service_account_names":      testRoleConfig.BoundServiceAccountNames,
		"bound_service_account_namespaces": testRoleConfig.BoundServiceAccountNamespaces,
		"audience":                         testRoleConfig.Audience,
		"alias_name_source":                testRoleConfig.AliasNameSource,
		"token_ttl":                        testRoleConfig.TokenTTL,
		"token_max_ttl":                    testRoleConfig.TokenMaxTTL,
		"token_policies":                   testRoleConfig.TokenPolicies,
		"token_bound_cidrs":                testRoleConfig.TokenBoundCIDRs,
		"token_explicit_max_ttl":           testRoleConfig.TokenExplicitMaxTTL,
		"token_no_default_policy":          testRoleConfig.TokenNoDefaultPolicy,
		"token_num_uses":                   testRoleConfig.TokenNumUses,
		"token_period":                     testRoleConfig.TokenPeriod,
		"token_type":                       testRoleConfig.TokenType,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing Kubernetes role: %v", err)
	}

	// Load JWT
	jwt, err := readTokenFromFile(defaultServiceAccountTokenPath)
	if err != nil {
		return nil, err
	}

	return &kubernetestest{
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		roleName:   testRoleConfig.Name,
		jwt:        jwt,
	}, nil
}

func readTokenFromFile(filepath string) (string, error) {
	jwt, err := os.ReadFile(filepath)
	if err != nil {
		return "", fmt.Errorf("unable to read file containing service account token: %w", err)
	}
	return string(jwt), nil
}
