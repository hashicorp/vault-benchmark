// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	SyncDestinationCreate = "destination_create"
)

func init() {
	TestList[SyncDestinationCreate] = func() BenchmarkBuilder {
		return &SecretSyncDestination{
			target: SyncDestinationCreate,
		}
	}
}

type SecretSyncDestination struct {
	target     string
	mount      string
	pathPrefix string

	config *SecretSyncDestinationConfig

	logger hclog.Logger
}

type SecretSyncDestinationConfig struct {
	NumDestinations   int               `hcl:"num_destinations,optional"`
	DestinationType   string            `hcl:"destination_type"`
	DestinationName   string            `hcl:"destination_name,optional"`
	DestinationConfig map[string]string `hcl:"destination_config,optional"`
}

func (t *SecretSyncDestination) ParseConfig(body hcl.Body) error {
	cfg := &struct {
		Config *SecretSyncDestinationConfig `hcl:"config,block"`
	}{
		// Defaults
		Config: &SecretSyncDestinationConfig{
			NumDestinations:   3,
			DestinationName:   fmt.Sprintf("benchmark-test-%s", uuid.New().String()),
			DestinationConfig: map[string]string{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, cfg)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	t.config = cfg.Config
	t.pathPrefix = "/v1/sys/sync/destinations/" + t.config.DestinationType + "/" + t.config.DestinationName

	return nil
}

func (t *SecretSyncDestination) Flags(_ *flag.FlagSet) {}

func (t *SecretSyncDestination) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	t.logger = targetLogger.Named(t.target)

	// No setup needed - destinations will be created during benchmark

	return &SecretSyncDestination{
		pathPrefix: t.pathPrefix,
		target:     t.target,
		config:     t.config,
		mount:      mountName,
		logger:     t.logger,
	}, nil
}

func (t *SecretSyncDestination) Cleanup(client *api.Client) error {
	// Delete destination created during benchmark
	t.logger.Debug("deleting destination", "type", t.config.DestinationType, "name", t.config.DestinationName)
	_, err := client.Logical().Delete(
		fmt.Sprintf("/sys/sync/destinations/%s/%s", t.config.DestinationType, t.config.DestinationName),
	)
	if err != nil {
		t.logger.Error("failed to clean destination", "type", t.config.DestinationType, "name", t.config.DestinationName, "error", err)
	}

	return nil
}

func (t *SecretSyncDestination) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     http.MethodPost,
		pathPrefix: t.pathPrefix,
	}
}

func (t *SecretSyncDestination) Target(client *api.Client) vegeta.Target {
	// Prepare destination config body
	body := map[string]any{}
	if err := mapstructure.Decode(t.config.DestinationConfig, &body); err != nil {
		t.logger.Error("error decoding destination config", "error", err)
	}

	// Marshal body to JSON
	body["name"] = t.config.DestinationName
	bodyBytes, _ := json.Marshal(body)

	return vegeta.Target{
		Method: t.GetTargetInfo().method,
		URL: fmt.Sprintf("%s/v1/sys/sync/destinations/%s/%s",
			client.Address(),
			t.config.DestinationType,
			t.config.DestinationName,
		),
		Header: http.Header{
			vaultTokenHeader:     []string{client.Token()},
			vaultNamespaceHeader: []string{client.Namespace()},
		},
		Body: bodyBytes,
	}
}
