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
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	KVV2ReadTestType    = "kvv2_read"
	KVV2WriteTestType   = "kvv2_write"
	KVV2ReadTestMethod  = "GET"
	KVV2WriteTestMethod = "POST"
)

func init() {
	TestList[KVV2ReadTestType] = func() BenchmarkBuilder {
		return &KVV2Secret{action: "read"}
	}
	TestList[KVV2WriteTestType] = func() BenchmarkBuilder {
		return &KVV2Secret{action: "write"}
	}
}

type KVV2Secret struct {
	pathPrefix string
	header     http.Header
	writeBody  []byte
	config     *KVV2SecretConfig
	action     string
	numKVs     int
	logger     hclog.Logger
}

type KVV2SecretConfig struct {
	KVSize int `hcl:"kvsize,optional"`
	NumKVs int `hcl:"numkvs,optional"`
}

func (k *KVV2Secret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *KVV2SecretConfig `hcl:"config,block"`
	}{
		Config: &KVV2SecretConfig{
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

func (k *KVV2Secret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	mountPath := mountName
	switch k.action {
	case "write":
		k.logger = targetLogger.Named(KVV2WriteTestType)
	default:
		k.logger = targetLogger.Named(KVV2ReadTestType)
	}

	mountPath, err = resolveMountPath(mountPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	k.logger.Trace(mountLogMessage("secrets", "kvv2", mountPath))
	err = client.Sys().Mount(mountPath, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
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

	// KV v2 mount upgrade is asynchronous; writes fail briefly with "Upgrading from non-versioned to versioned data."
	// TODO: replace sleep with a poll once Vault exposes a readiness signal for KV v2.
	time.Sleep(2 * time.Second)

	if err := runPhase(setupLogger, "seed secrets", kvSeedConcurrency, k.config.NumKVs, func(idx int) error {
		_, err := client.Logical().Write(mountPath+"/data/secret-"+strconv.Itoa(idx+1), secval)
		if err != nil {
			return fmt.Errorf("error writing kvv2 secret: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &KVV2Secret{
		pathPrefix: "/v1/" + mountPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		numKVs:     k.config.NumKVs,
		writeBody:  fmt.Appendf(nil, `{"data": {"foo": "%s"}}`, strings.Repeat("a", k.config.KVSize)),
		logger:     k.logger,
		action:     k.action,
	}, nil
}

func (k *KVV2Secret) Target(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	t := vegeta.Target{
		Method: KVV2ReadTestMethod,
		URL:    client.Address() + k.pathPrefix + "/data/secret-" + strconv.Itoa(secnum),
		Header: k.header,
	}
	if k.action == "write" {
		t.Method = KVV2WriteTestMethod
		t.Body = k.writeBody
	}
	return t
}

func (k *KVV2Secret) Cleanup(client *api.Client) error {
	return cleanupMount(k.logger, client, k.pathPrefix)
}

func (k *KVV2Secret) GetTargetInfo() TargetInfo {
	var method string
	switch k.action {
	case "write":
		method = KVV2WriteTestMethod
	default:
		method = KVV2ReadTestMethod
	}
	return TargetInfo{
		method:     method,
		pathPrefix: k.pathPrefix,
	}
}

func (k *KVV2Secret) Flags(fs *flag.FlagSet) {}
