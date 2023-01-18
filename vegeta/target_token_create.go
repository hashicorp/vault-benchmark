package vegeta

import (
	"net/http"

	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type tokenCreateTest struct {
	header http.Header
}

func (t *tokenCreateTest) createService(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + "/v1/auth/token/create",
		Body:   []byte(`{"data": {"policies": ["default"], "type": "service"}}`),
		Header: t.header,
	}
}

func (t *tokenCreateTest) createBatch(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + "/v1/auth/token/create",
		Body:   []byte(`{"policies":["path \"auth/token/create\" {\n   capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}"],"ttl":"20m0s","explicit_max_ttl":"0s","period":"0s","display_name":"","num_uses":0,"renewable":false,"type":"batch","entity_alias":""}`),
		Header: t.header,
	}
}

// Cleanup is a no-op for this test
func (t *tokenCreateTest) cleanup(client *api.Client) error {
	return nil
}

func setupToken(client *api.Client) *tokenCreateTest {
	return &tokenCreateTest{
		header: http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}
}
