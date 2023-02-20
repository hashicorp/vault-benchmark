package benchmarktests

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	KVV1ReadTestType    = "kvv1_read"
	KVV1WriteTestType   = "kvv1_write"
	KVV1ReadTestMethod  = "GET"
	KVV1WriteTestMethod = "POST"
)

func init() {
	TestList[KVV1ReadTestType] = func() BenchmarkBuilder {
		return &kvv1_test{action: "read"}
	}
	TestList[KVV1WriteTestType] = func() BenchmarkBuilder {
		return &kvv1_test{action: "write"}
	}
}

type kvv1_test struct {
	pathPrefix string
	header     http.Header
	config     *KVV1TestConfig
	action     string
	numKVs     int
	kvSize     int
}

type KVV1TestConfig struct {
	Config *KVV1Config `hcl:"config,block"`
}

type KVV1Config struct {
	KVSize int `hcl:"kvsize,optional"`
	NumKVs int `hcl:"numkvs,optional"`
}

func (k *kvv1_test) ParseConfig(body hcl.Body) error {
	k.config = &KVV1TestConfig{
		Config: &KVV1Config{
			KVSize: 1,
			NumKVs: 1000,
		},
	}

	diags := gohcl.DecodeBody(body, nil, k.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	return nil
}

func (k *kvv1_test) read(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	return vegeta.Target{
		Method: KVV1ReadTestMethod,
		URL:    client.Address() + k.pathPrefix + "/secret-" + strconv.Itoa(secnum),
		Header: k.header,
	}
}

func (k *kvv1_test) write(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	value := strings.Repeat("a", k.kvSize)
	return vegeta.Target{
		Method: KVV1WriteTestMethod,
		URL:    client.Address() + k.pathPrefix + "/secret-" + strconv.Itoa(secnum),
		Body:   []byte(`{"data": {"foo": "` + value + `"}}`),
		Header: k.header,
	}
}

func (k *kvv1_test) Target(client *api.Client) vegeta.Target {
	switch k.action {
	case "write":
		return k.write(client)
	default:
		return k.read(client)
	}
}

func (k *kvv1_test) GetTargetInfo() TargetInfo {
	var method string
	switch k.action {
	case "write":
		method = KVV1WriteTestMethod
	default:
		method = KVV1ReadTestMethod
	}
	tInfo := TargetInfo{
		method:     method,
		pathPrefix: k.pathPrefix,
	}
	return tInfo
}

func (k *kvv1_test) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(k.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (k *kvv1_test) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	mountPath := mountName
	config := k.config.Config

	if randomMountName {
		mountPath, err = uuid.GenerateUUID()
		if err != nil {
			panic("can't create UUID")
		}
	}

	var setupIndex string
	err = client.WithResponseCallbacks(api.RecordState(&setupIndex)).Sys().Mount(mountPath, &api.MountInput{
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
	for i := 1; i <= config.NumKVs; i++ {
		if i == config.NumKVs-1 {
			client = client.WithResponseCallbacks(api.RecordState(&lastIndex))
		}
		_, err = client.Logical().Write(mountPath+"/secret-"+strconv.Itoa(i), secval)
		if err != nil {
			return nil, fmt.Errorf("error writing kvv1: %v", err)
		}
	}

	headers := http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}}
	if lastIndex != "" {
		headers["X-Vault-Index"] = []string{lastIndex}
	}
	return &kvv1_test{
		pathPrefix: "/v1/" + mountPath,
		action:     k.action,
		header:     headers,
		numKVs:     k.config.Config.NumKVs,
		kvSize:     k.config.Config.KVSize,
	}, nil
}

func (k *kvv1_test) Flags(fs *flag.FlagSet) {}
