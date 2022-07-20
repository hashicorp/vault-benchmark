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

type certTest struct {
	pathPrefix string
	header     http.Header
}

func setupCert(client *api.Client, randomMounts bool, ttl time.Duration, caPEM string) (*certTest, error) {
	authPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		authPath = "cert"
	}

	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling cert: %v", err)
	}

	role := "role1"
	rolePath := filepath.Join("auth", authPath, "certs", role)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"token_ttl":     int(ttl.Seconds()),
		"token_max_ttl": int(ttl.Seconds()),
		"certificate":   caPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating cert role %q: %v", role, err)
	}

	return &certTest{
		pathPrefix: "/v1/auth/" + authPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}, nil
}

func (c *certTest) login(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + c.pathPrefix + "/login",
		Header: c.header,
	}
}
