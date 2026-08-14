// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	KVV1ReadTestType    = "kvv1_read"
	KVV1WriteTestType   = "kvv1_write"
	KVV1ReadTestMethod  = "GET"
	KVV1WriteTestMethod = "POST"
)

func init() {
	TestList[KVV1ReadTestType] = func() BenchmarkBuilder {
		return &KVV1Secret{action: "read"}
	}
	TestList[KVV1WriteTestType] = func() BenchmarkBuilder {
		return &KVV1Secret{action: "write"}
	}
}

type KVV1Secret struct {
	pathPrefix string
	header     http.Header
	writeBody  []byte
	config     *KVV1SecretConfig
	action     string
	numKVs     int
	logger     hclog.Logger
}

type KVV1SecretConfig struct {
	KVSize int `hcl:"kvsize,optional"`
	NumKVs int `hcl:"numkvs,optional"`
}

func (k *KVV1Secret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *KVV1SecretConfig `hcl:"config,block"`
	}{
		Config: &KVV1SecretConfig{
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

func (k *KVV1Secret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	mountPath := mountName
	k.logger = targetLogger.Named("kvv1")

	mountPath, err = resolveMountPath(mountPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
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

	secval := map[string]any{
		"data": map[string]any{
			"foo": 1,
		},
	}

	if setupIndex != "" {
		client = client.WithRequestCallbacks(api.RequireState(setupIndex))
	}

	if err := runPhase(setupLogger, "seed secrets", kvSeedConcurrency, k.config.NumKVs, func(idx int) error {
		_, err := client.Logical().Write(mountPath+"/secret-"+strconv.Itoa(idx+1), secval)
		if err != nil {
			return fmt.Errorf("error writing kvv1 secret: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	var lastIndex string
	_, err = client.WithResponseCallbacks(api.RecordState(&lastIndex)).Logical().Write(mountPath+"/secret-0", secval)
	if err != nil {
		return nil, fmt.Errorf("error writing kvv1 replication probe: %w", err)
	}

	headers := http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}}
	if lastIndex != "" {
		headers["X-Vault-Index"] = []string{lastIndex}
	}
	return &KVV1Secret{
		pathPrefix: "/v1/" + mountPath,
		action:     k.action,
		header:     headers,
		numKVs:     k.config.NumKVs,
		writeBody:  fmt.Appendf(nil, `{"data": {"foo": "%s"}}`, strings.Repeat("a", k.config.KVSize)),
		logger:     k.logger,
	}, nil
}

func (k *KVV1Secret) Target(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	t := vegeta.Target{
		Method: KVV1ReadTestMethod,
		URL:    client.Address() + k.pathPrefix + "/secret-" + strconv.Itoa(secnum),
		Header: k.header,
	}
	if k.action == "write" {
		t.Method = KVV1WriteTestMethod
		t.Body = k.writeBody
	}
	return t
}

func (k *KVV1Secret) Cleanup(client *api.Client) error {
	return cleanupMount(k.logger, client, k.pathPrefix)
}

func (k *KVV1Secret) GetTargetInfo() TargetInfo {
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

func (k *KVV1Secret) Flags(fs *flag.FlagSet) {}
