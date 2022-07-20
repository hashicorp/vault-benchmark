package vegeta

import (
	"fmt"
	"net/http"
	"path/filepath"
	"time"

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

func (a *approletest) login(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   []byte(fmt.Sprintf(`{"role_id": "%s", "secret_id": "%s"}`, a.roleID, a.secretID)),
	}
}

func setupApprole(client *api.Client, randomMounts bool, ttl time.Duration) (*approletest, error) {
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

	role := "role1"
	rolePath := filepath.Join("auth", authPath, "role", role)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"token_ttl":     int(ttl.Seconds()),
		"token_max_ttl": int(ttl.Seconds()),
		"secret_id_ttl": int((1000 * time.Hour).Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating approle role %q: %v", role, err)
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
		role:       role,
		secretID:   secretId.Data["secret_id"].(string),
	}, nil
}
