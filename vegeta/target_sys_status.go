package vegeta

import (
	"net/http"

	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type statusTest struct {
	path   string
	header http.Header
}

func setupStatusTest(path string, client *api.Client) *statusTest {
	return &statusTest{
		path:   path,
		header: http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}
}

func (s *statusTest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + s.path,
		Header: s.header,
	}
}

// Cleanup is a no-op for this test
func (s *statusTest) cleanup(client *api.Client) error {
	return nil
}
