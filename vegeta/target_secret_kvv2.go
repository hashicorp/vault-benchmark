package vegeta

import (
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type kvv2test struct {
	pathPrefix string
	header     http.Header
	numKVs     int
	kvSize     int
}

func (k *kvv2test) read(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + k.pathPrefix + "/data/secret-" + strconv.Itoa(secnum),
		Header: k.header,
	}
}

func (k *kvv2test) write(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	value := strings.Repeat("a", k.kvSize)
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + k.pathPrefix + "/data/secret-" + strconv.Itoa(secnum),
		Header: k.header,
		Body:   []byte(`{"data": {"foo": "` + value + `"}}`),
	}
}

func setupKvv2(client *api.Client, randomMounts bool, sealWrap bool, numKVs int, kvSize int) (*kvv2test, error) {
	kvv2Path, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		kvv2Path = "kvv2"
	}

	err = client.Sys().Mount(kvv2Path, &api.MountInput{
		Type:     "kv",
		SealWrap: sealWrap,
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting kvv2: %v", err)
	}

	secval := map[string]interface{}{
		"data": map[string]interface{}{
			"foo": 1,
		},
	}

	// Avoid error of the form:
	// * Upgrading from non-versioned to versioned data. This backend will be unavailable for a brief period and will resume service shortly.
	time.Sleep(2 * time.Second)

	for i := 1; i <= numKVs; i++ {
		_, err = client.Logical().Write(kvv2Path+"/data/secret-"+strconv.Itoa(i), secval)
		if err != nil {
			return nil, fmt.Errorf("error writing kv: %v", err)
		}
	}

	return &kvv2test{
		pathPrefix: "/v1/" + kvv2Path,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		numKVs:     numKVs,
		kvSize:     kvSize,
	}, nil
}
