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

type userpasstest struct {
	pathPrefix string
	role       string
	password   string
	header     http.Header
}

type UserpassRoleConfig struct {
	RoleName            string   `json:"role_name"`
	Username            string   `json:"username"`
	Password            string   `json:"password"`
	TokenTTL            string   `json:"token_ttl"`
	TokenMaxTTL         string   `json:"token_max_ttl"`
	TokenPolicies       []string `json:"token_policies"`
	TokenExplicitMaxTTL string   `json:"token_explicit_max_ttl"`
	TokenType           string   `json:"token_type"`
}

func (u *UserpassRoleConfig) FromJSON(path string) error {
	if path == "" {
		return fmt.Errorf("no redis config passed but is required")
	}

	// defaults
	defaultRoleName := "benchmark-role"
	defaultTTL := "0s"
	defaultTokenPolicies := []string{"default"}
	defaultTokenType := "default"

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(u); err != nil {
		return err
	}

	// Check for required fields in RedisConfig
	switch {
	case u.Username == "":
		return fmt.Errorf("no username passed but is required")
	case u.Password == "":
		return fmt.Errorf("no password passed but is required")
	}

	if u.RoleName == "" {
		u.RoleName = defaultRoleName
	}

	if u.TokenTTL == "" {
		u.TokenTTL = defaultTTL
	}

	if u.TokenMaxTTL == "" {
		u.TokenMaxTTL = defaultTTL
	}

	if u.TokenExplicitMaxTTL == "" {
		u.TokenExplicitMaxTTL = defaultTTL
	}

	if len(u.TokenPolicies) == 0 {
		u.TokenPolicies = defaultTokenPolicies
	}

	if u.TokenType == "" {
		u.TokenType = defaultTokenType
	}

	return nil
}

func (u *userpasstest) login(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + u.pathPrefix + "/login/" + u.role,
		Header: u.header,
		Body:   []byte(fmt.Sprintf(`{"password": "%s"}`, u.password)),
	}
}

func (a *userpasstest) cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(a.pathPrefix, "/v1/", "/sys/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupUserpass(client *api.Client, randomMounts bool, config *UserpassRoleConfig) (*userpasstest, error) {
	authPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		authPath = "userpass"
	}

	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling userpass: %v", err)
	}

	rolePath := filepath.Join("auth", authPath, "users", config.RoleName)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"token_ttl":              config.TokenTTL,
		"token_max_ttl":          config.TokenMaxTTL,
		"token_explicit_max_ttl": config.TokenExplicitMaxTTL,
		"token_policies":         config.TokenPolicies,
		"token_type":             config.TokenType,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating userpass role %q: %v", config.RoleName, err)
	}

	return &userpasstest{
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		role:       config.RoleName,
		password:   config.Password,
	}, nil
}
