// Copyright (c) HashiCorp, Inc.
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

const (
	TOTPReadTestType    = "totp_read"
	TOTPWriteTestType   = "totp_write"
	TOTPReadTestMethod  = "GET"
	TOTPWriteTestMethod = "POST"
)

func init() {
	TestList[TOTPReadTestType] = func() BenchmarkBuilder { return &TOTPTest{action: "read"} }
	TestList[TOTPWriteTestType] = func() BenchmarkBuilder { return &TOTPTest{action: "write"} }
}

type TOTPTest struct {
	pathPrefix string
	header     http.Header
	config     *TOTPSecretTestConfig
	numkeys    int
	keysize    int
	action     string
	logger     hclog.Logger
}

type TOTPSecretTestConfig struct {
	NumKeys int `hcl:"numkeys,optional"`
	KeySize int `hcl:"keysize,optional"`
}

func (a *TOTPTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *TOTPSecretTestConfig `hcl:"config,block"`
	}{
		Config: &TOTPSecretTestConfig{
			KeySize: 20,
			NumKeys: 1000,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	a.config = testConfig.Config

	return nil
}

func (t *TOTPTest) read(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(t.numkeys)))
	return vegeta.Target{
		Method: TOTPReadTestMethod,
		URL:    client.Address() + t.pathPrefix + "/code/" + strconv.Itoa(secnum),
		Header: t.header,
	}
}

func (t *TOTPTest) write(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(t.numkeys)))
	return vegeta.Target{
		Method: TOTPWriteTestMethod,
		URL:    client.Address() + t.pathPrefix + "/keys/write-test-" + strconv.Itoa(secnum),
		Header: t.header,
		Body:   []byte(`{"name":"` + strconv.Itoa(secnum) + `","generate":true,"issuer":"Vault","account_name":"test@example.com"}`),
	}
}

func (t *TOTPTest) Target(client *api.Client) vegeta.Target {
	switch t.action {
	case "write":
		return t.write(client)
	default:
		return t.read(client)
	}
}

func (t *TOTPTest) Cleanup(client *api.Client) error {
	t.logger.Trace(cleanupLogMessage(t.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(t.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (t *TOTPTest) GetTargetInfo() TargetInfo {
	var method string
	switch t.action {
	case "write":
		method = TOTPWriteTestMethod
	default:
		method = TOTPReadTestMethod
	}
	return TargetInfo{
		method:     method,
		pathPrefix: t.pathPrefix,
	}
}

func (t *TOTPTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName

	switch t.action {
	case "write":
		t.logger = targetLogger.Named(TOTPWriteTestType)
	default:
		t.logger = targetLogger.Named(TOTPReadTestType)
	}

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	t.logger.Trace(mountLogMessage("secrets", "totp", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "totp",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting totp secrets engine: %v", err)
	}

	secval := map[string]interface{}{
		"generate":     true,
		"issuer":       "Vault",
		"account_name": "test@example.com",
	}

	setupLogger := t.logger.Named(secretPath)
	setupLogger.Trace("seeding secrets")
	for i := 1; i <= t.config.NumKeys; i++ {
		_, err := client.Logical().Write(secretPath+"/keys/"+strconv.Itoa(i), secval)
		if err != nil {
			return nil, fmt.Errorf("failed to seed totp secret: %w", err)
		}
	}

	return &TOTPTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		logger:     t.logger,
		numkeys:    t.config.NumKeys,
		keysize:    t.config.KeySize,
		action:     t.action,
	}, nil
}

func (a *TOTPTest) Flags(fs *flag.FlagSet) {}
