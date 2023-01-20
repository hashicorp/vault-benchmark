package vegeta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type approletest struct {
	pathPrefix string
	role       string
	roleID     string
	header     http.Header
	secretID   string
}

type AppRoleConfig struct {
	RoleName      string   `json:"role_name"`
	SecretIDTTL   string   `json:"secret_id_ttl"`
	TokenTTL      string   `json:"token_ttl"`
	TokenMaxTTL   string   `json:"token_max_ttl"`
	TokenPolicies []string `json:"token_policies"`
	TokenType     string   `json:"token_type"`
}

func (a *AppRoleConfig) FromJSON(path string) error {
	if path == "" {
		return nil
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(a); err != nil {
		return err
	}

	// Set defaults
	defaultRoleName := "benchmark-role"
	defaultTTL := "0s"
	defaultTokenPolicies := []string{"default"}
	defaultTokenType := "default"

	if a.RoleName == "" {
		a.RoleName = defaultRoleName
	}

	if a.SecretIDTTL == "" {
		a.SecretIDTTL = defaultTTL
	}

	if a.TokenMaxTTL == "" {
		a.TokenMaxTTL = defaultTTL
	}

	if a.TokenTTL == "" {
		a.TokenTTL = defaultTTL
	}

	if len(a.TokenPolicies) == 0 {
		a.TokenPolicies = defaultTokenPolicies
	}

	if a.TokenType == "" {
		a.TokenType = defaultTokenType
	}

	return nil
}

func (a *approletest) login(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   []byte(fmt.Sprintf(`{"role_id": "%s", "secret_id": "%s"}`, a.roleID, a.secretID)),
	}
}

func (a *approletest) cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(a.pathPrefix, "/v1/", "/sys/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupApprole(client *api.Client, randomMounts bool, config *AppRoleConfig) (*approletest, error) {
	authPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		authPath = "approle"
	}

	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling approle: %v", err)
	}

	rolePath := filepath.Join("auth", authPath, "role", config.RoleName)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"token_ttl":      config.TokenTTL,
		"token_max_ttl":  config.TokenMaxTTL,
		"secret_id_ttl":  config.SecretIDTTL,
		"token_policies": config.TokenPolicies,
		"token_type":     config.TokenType,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating approle role %q: %v", config.RoleName, err)
	}

	secretRole, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return nil, fmt.Errorf("error reading approle role_id: %v", err)
	}

	secretId, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		return nil, fmt.Errorf("error reading approle secret_id: %v", err)
	}

	return &approletest{
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		roleID:     secretRole.Data["role_id"].(string),
		role:       config.RoleName,
		secretID:   secretId.Data["secret_id"].(string),
	}, nil
}
