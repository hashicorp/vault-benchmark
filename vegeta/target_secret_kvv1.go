package vegeta

import (
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type kvv1test struct {
	pathPrefix string
	header     http.Header
	numKVs     int
	kvSize     int
}

func (k *kvv1test) read(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + k.pathPrefix + "/secret-" + strconv.Itoa(secnum),
		Header: k.header,
	}
}

func (k *kvv1test) write(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	value := strings.Repeat("a", k.kvSize)
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + k.pathPrefix + "/secret-" + strconv.Itoa(secnum),
		Body:   []byte(`{"data": {"foo": "` + value + `"}}`),
		Header: k.header,
	}
}

func setupKvv1(client *api.Client, randomMounts bool, numKVs int, kvSize int) (*kvv1test, error) {
	kvv1Path, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		kvv1Path = "kvv1"
	}

	var setupIndex string
	err = client.WithResponseCallbacks(api.RecordState(&setupIndex)).Sys().Mount(kvv1Path, &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting kvv1: %v", err)
	}

	secval := map[string]interface{}{
		"data": map[string]interface{}{
			"foo": 1,
		},
	}
	if setupIndex != "" {
		client = client.WithRequestCallbacks(api.RequireState(setupIndex))
	}
	var lastIndex string
	for i := 1; i <= numKVs; i++ {
		if i == numKVs-1 {
			client = client.WithResponseCallbacks(api.RecordState(&lastIndex))
		}
		_, err = client.Logical().Write(kvv1Path+"/secret-"+strconv.Itoa(i), secval)
		if err != nil {
			return nil, fmt.Errorf("error writing kvv1: %v", err)
		}
	}

	headers := http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}}
	if lastIndex != "" {
		headers["X-Vault-Index"] = []string{lastIndex}
	}
	return &kvv1test{
		pathPrefix: "/v1/" + kvv1Path,
		header:     headers,
		numKVs:     numKVs,
		kvSize:     kvSize,
	}, nil
}
