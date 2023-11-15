// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
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
	SyncEvents            = "events"
	SyncAssociationsWrite = "associations_write"
	SyncAssociationsRead  = "associations_read"

	secretNameFormat     = "my-benchmark-secret-%d"
	vaultTokenHeader     = "X-Vault-Token"
	vaultNamespaceHeader = "X-Vault-Namespace"
)

func init() {
	TestList[SyncEvents] = func() BenchmarkBuilder {
		return &SyncAWSTest{
			target: SyncEvents,
		}
	}
	TestList[SyncAssociationsWrite] = func() BenchmarkBuilder {
		return &SyncAWSTest{
			target: SyncAssociationsWrite,
		}
	}
	TestList[SyncAssociationsRead] = func() BenchmarkBuilder {
		return &SyncAWSTest{
			target: SyncAssociationsRead,
		}
	}
}

type SyncAWSTest struct {
	target string
	mount  string

	config *SyncAWSTestConfig

	logger hclog.Logger
}

type SyncAWSTestConfig struct {
	NumAssociations   int               `hcl:"num_associations,optional"`
	DestinationType   string            `hcl:"destination_type"`
	DestinationName   string            `hcl:"destination_name"`
	DestinationConfig map[string]string `hcl:"destination_config,optional"`
}

func (t *SyncAWSTest) ParseConfig(body hcl.Body) error {
	cfg := &struct {
		Config *SyncAWSTestConfig `hcl:"config,block"`
	}{
		// Defaults
		Config: &SyncAWSTestConfig{
			NumAssociations:   1,
			DestinationConfig: map[string]string{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, cfg)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	t.config = cfg.Config

	return nil
}

func (t *SyncAWSTest) Flags(_ *flag.FlagSet) {}

func (t *SyncAWSTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	t.logger = targetLogger.Named(t.target)

	// Create test mount
	t.logger.Debug(mountLogMessage("secrets", "kvv2", mountName))

	if topLevelConfig.RandomMounts {
		mountName += "-" + uuid.New().String()
	}
	err := client.Sys().Mount(mountName, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error setupping KVv2 engine: %v", err)
	}

	// Create 1 secret to sync per association
	for i := 0; i < t.config.NumAssociations; i++ {
		secretName := fmt.Sprintf(secretNameFormat, i)
		t.logger.Debug("creating secret on test mount", "mount", t.mount, "secret", secretName)

		_, err := client.KVv2(mountName).Put(context.Background(), secretName, map[string]any{"key": uuid.New().String()})
		if err != nil {
			return nil, fmt.Errorf("error setupping secrets: %w", err)
		}
	}

	// Create the test destination
	t.logger.Debug("creating destination", "type", t.config.DestinationType, "name", t.config.DestinationName)

	body := map[string]any{}
	if err := mapstructure.Decode(t.config.DestinationConfig, &body); err != nil {
		return nil, fmt.Errorf("error decoding destination config: %w", err)
	}

	_, err = client.Logical().Write(
		fmt.Sprintf("/%s/destinations/%s/%s", t.GetTargetInfo().pathPrefix, t.config.DestinationType, t.config.DestinationName),
		body,
	)
	if err != nil {
		return nil, fmt.Errorf("error setupping destination: %w", err)
	}

	// If test is read or event based, pre-populate the associations
	if t.target == SyncEvents || t.target == SyncAssociationsRead {
		for i := 0; i < t.config.NumAssociations; i++ {
			secretName := fmt.Sprintf(secretNameFormat, i)
			t.logger.Debug("creating association", "mount", mountName, "secret", secretName)

			_, err = client.Logical().Write(
				fmt.Sprintf("/%s/destinations/%s/%s/associations/set", t.GetTargetInfo().pathPrefix, t.config.DestinationType, t.config.DestinationName),
				map[string]any{"mount": mountName, "secret_name": secretName},
			)
			if err != nil {
				return nil, fmt.Errorf("error setupping associations: %w", err)
			}
		}
	}

	return &SyncAWSTest{
		target: t.target,
		config: t.config,
		mount:  mountName,
		logger: t.logger,
	}, nil
}

func (t *SyncAWSTest) Cleanup(client *api.Client) error {
	// Delete associations
	for i := 0; i < t.config.NumAssociations; i++ {
		secretName := fmt.Sprintf(secretNameFormat, i)
		t.logger.Debug("deleting association for test secret", "mount", t.mount, "secret", secretName)

		_, err := client.Logical().Write(
			fmt.Sprintf("/%s/destinations/%s/%s/associations/remove", t.GetTargetInfo().pathPrefix, t.config.DestinationType, t.config.DestinationName),
			map[string]any{"mount": t.mount, "secret_name": secretName},
		)
		if err != nil {
			t.logger.Error("failed to clean association", "mount", t.mount, "secret", secretName, "error", err)
		}
	}

	// Delete destination
	t.logger.Debug("deleting destination", "type", t.config.DestinationType, "name", t.config.DestinationName)
	_, err := client.Logical().Delete(
		fmt.Sprintf("/%s/destinations/%s/%s", t.GetTargetInfo().pathPrefix, t.config.DestinationType, t.config.DestinationName),
	)
	if err != nil {
		t.logger.Error("failed to clean destination", "type", t.config.DestinationType, "name", t.config.DestinationName, "error", err)
	}

	// Delete secrets
	for i := 0; i < t.config.NumAssociations; i++ {
		secretName := fmt.Sprintf(secretNameFormat, i)
		t.logger.Debug("deleting test secret", "mount", t.mount, "secret", secretName)

		err := client.KVv2(t.mount).Delete(context.Background(), fmt.Sprintf(secretNameFormat, i))
		if err != nil {
			t.logger.Error("failed to clean test secret", "mount", t.mount, "secret", secretName, "error", err)
		}
	}

	// Unmount KVv2 engine
	t.logger.Debug("deleting test engine", "mount", t.mount)
	err = client.Sys().Unmount(t.mount)
	if err != nil {
		t.logger.Error("failed to unmount test engine", "mount", t.mount)
	}

	return nil
}

func (t *SyncAWSTest) GetTargetInfo() TargetInfo {
	var method string
	switch t.target {
	case SyncAssociationsRead:
		method = http.MethodGet
	default:
		method = http.MethodPost
	}

	return TargetInfo{
		method:     method,
		pathPrefix: "sys/sync",
	}
}

func (t *SyncAWSTest) Target(client *api.Client) vegeta.Target {
	switch t.target {
	case SyncEvents:
		return t.events(client)
	case SyncAssociationsWrite:
		return t.write(client)
	default:
		return t.read(client)
	}
}

func (t *SyncAWSTest) events(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: t.GetTargetInfo().method,
		URL: fmt.Sprintf("%s/v1/%s/data/%s",
			client.Address(),
			t.mount,
			fmt.Sprintf(secretNameFormat,
				int(rand.Int31n(int32(t.config.NumAssociations))),
			),
		),
		Header: http.Header{
			vaultTokenHeader:     []string{client.Token()},
			vaultNamespaceHeader: []string{client.Namespace()}},
		Body: []byte(
			fmt.Sprintf(`{"data": {"foo": "%s"}}`,
				uuid.New().String(),
			),
		),
	}
}

func (t *SyncAWSTest) write(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: t.GetTargetInfo().method,
		URL: fmt.Sprintf("%s/v1/%s/destinations/%s/%s/associations/set",
			client.Address(),
			t.GetTargetInfo().pathPrefix,
			t.config.DestinationType,
			t.config.DestinationName,
		),
		Header: http.Header{
			vaultTokenHeader:     []string{client.Token()},
			vaultNamespaceHeader: []string{client.Namespace()}},
		Body: []byte(
			fmt.Sprintf(`{"mount": "%s", "secret_name": "%s"}`,
				t.mount,
				fmt.Sprintf(secretNameFormat,
					int(rand.Int31n(int32(t.config.NumAssociations))),
				),
			),
		),
	}
}

func (t *SyncAWSTest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: t.GetTargetInfo().method,
		URL: fmt.Sprintf("%s/v1/%s/associations/destinations?mount=%s&secret_name=%s",
			client.Address(),
			t.GetTargetInfo().pathPrefix,
			t.mount,
			fmt.Sprintf(secretNameFormat,
				int(rand.Int31n(int32(t.config.NumAssociations))),
			),
		),
		Header: http.Header{
			vaultTokenHeader:     []string{client.Token()},
			vaultNamespaceHeader: []string{client.Namespace()}},
	}
}
