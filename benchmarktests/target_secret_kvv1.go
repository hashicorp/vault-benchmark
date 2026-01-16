// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
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
		return &KVV1Test{action: "read"}
	}
	TestList[KVV1WriteTestType] = func() BenchmarkBuilder {
		return &KVV1Test{action: "write"}
	}
}

type KVV1Test struct {
	pathPrefix string
	header     http.Header
	config     *KVV1SecretTestConfig
	action     string
	numKVs     int
	kvSize     int
	logger     hclog.Logger
}

type KVV1SecretTestConfig struct {
	KVSize int `hcl:"kvsize,optional"`
	NumKVs int `hcl:"numkvs,optional"`
}

func (k *KVV1Test) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *KVV1SecretTestConfig `hcl:"config,block"`
	}{
		Config: &KVV1SecretTestConfig{
			KVSize: 1,
			NumKVs: 1000,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	k.config = testConfig.Config
	return nil
}

func (k *KVV1Test) read(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	return vegeta.Target{
		Method: KVV1ReadTestMethod,
		URL:    client.Address() + k.pathPrefix + "/secret-" + strconv.Itoa(secnum),
		Header: k.header,
	}
}

func (k *KVV1Test) write(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	value := strings.Repeat("a", k.kvSize)
	return vegeta.Target{
		Method: KVV1WriteTestMethod,
		URL:    client.Address() + k.pathPrefix + "/secret-" + strconv.Itoa(secnum),
		Body:   []byte(`{"data": {"foo": "` + value + `"}}`),
		Header: k.header,
	}
}

func (k *KVV1Test) Target(client *api.Client) vegeta.Target {
	switch k.action {
	case "write":
		return k.write(client)
	default:
		return k.read(client)
	}
}

func (k *KVV1Test) GetTargetInfo() TargetInfo {
	var method string
	switch k.action {
	case "write":
		method = KVV1WriteTestMethod
	default:
		method = KVV1ReadTestMethod
	}
	return TargetInfo{
		method:     method,
		pathPrefix: k.pathPrefix,
	}
}

func (k *KVV1Test) Cleanup(client *api.Client) error {
	k.logger.Trace(cleanupLogMessage(k.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(k.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (k *KVV1Test) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	mountPath := mountName
	k.logger = targetLogger.Named("kvv1")

	if topLevelConfig.RandomMounts {
		mountPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	var setupIndex string
	k.logger.Trace(mountLogMessage("secrets", "kvv1", mountPath))
	err = client.WithResponseCallbacks(api.RecordState(&setupIndex)).Sys().Mount(mountPath, &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting kv secrets engine: %v", err)
	}

	setupLogger := k.logger.Named(mountPath)

	secval := map[string]interface{}{
		"data": map[string]interface{}{
			"foo": 1,
		},
	}

	if setupIndex != "" {
		client = client.WithRequestCallbacks(api.RequireState(setupIndex))
	}

	var lastIndex string
	setupLogger.Trace("seeding secrets")
	for i := 1; i <= k.config.NumKVs; i++ {
		if i == k.config.NumKVs-1 {
			client = client.WithResponseCallbacks(api.RecordState(&lastIndex))
		}
		_, err = client.Logical().Write(mountPath+"/secret-"+strconv.Itoa(i), secval)
		if err != nil {
			return nil, fmt.Errorf("error writing kvv1 secret: %v", err)
		}
	}

	headers := http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}}
	if lastIndex != "" {
		headers["X-Vault-Index"] = []string{lastIndex}
	}
	return &KVV1Test{
		pathPrefix: "/v1/" + mountPath,
		action:     k.action,
		header:     headers,
		numKVs:     k.config.NumKVs,
		kvSize:     k.config.KVSize,
		logger:     k.logger,
	}, nil
}

func (k *KVV1Test) Flags(fs *flag.FlagSet) {}
