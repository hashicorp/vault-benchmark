// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"time"

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
		return &AWSSync{
			target: SyncEvents,
		}
	}
	TestList[SyncAssociationsWrite] = func() BenchmarkBuilder {
		return &AWSSync{
			target: SyncAssociationsWrite,
		}
	}
	TestList[SyncAssociationsRead] = func() BenchmarkBuilder {
		return &AWSSync{
			target: SyncAssociationsRead,
		}
	}
}

type AWSSync struct {
	target     string
	mount      string
	method     string
	pathPrefix string

	config *AWSSyncConfig

	logger hclog.Logger
}

type AWSSyncConfig struct {
	NumAssociations   int               `hcl:"num_associations,optional"`
	DestinationType   string            `hcl:"destination_type"`
	DestinationName   string            `hcl:"destination_name,optional"`
	DestinationConfig map[string]string `hcl:"destination_config,optional"`
}

func (t *AWSSync) ParseConfig(body hcl.Body) error {
	cfg := &struct {
		Config *AWSSyncConfig `hcl:"config,block"`
	}{
		Config: &AWSSyncConfig{
			NumAssociations:   3,
			DestinationName:   fmt.Sprintf("benchmark-test-%s", uuid.New().String()),
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

func (t *AWSSync) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	t.logger = targetLogger.Named(t.target)

	if topLevelConfig.RandomMounts {
		mountName += "-" + uuid.New().String()
	}

	t.logger.Debug(mountLogMessage("secrets", "kvv2", mountName))
	err := client.Sys().Mount(mountName, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error setupping KVv2 engine: %v", err)
	}

	for i := range t.config.NumAssociations {
		secretName := fmt.Sprintf(secretNameFormat, i)
		t.logger.Debug("creating secret on test mount", "mount", mountName, "secret", secretName)

		_, err := client.KVv2(mountName).Put(context.Background(), secretName, map[string]any{"key": time.Now().Format(time.RFC3339)})
		if err != nil {
			return nil, fmt.Errorf("error setting up secrets: %w", err)
		}
	}

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

	if t.target == SyncEvents || t.target == SyncAssociationsRead {
		for i := range t.config.NumAssociations {
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

	method := http.MethodPost
	if t.target == SyncAssociationsRead {
		method = http.MethodGet
	}

	return &AWSSync{
		target:     t.target,
		config:     t.config,
		mount:      mountName,
		method:     method,
		pathPrefix: "sys/sync",
		logger:     t.logger,
	}, nil
}

func (t *AWSSync) Target(client *api.Client) vegeta.Target {
	n := int(rand.Int31n(int32(t.config.NumAssociations)))
	tgt := vegeta.Target{
		Method: t.method,
		URL: fmt.Sprintf("%s/v1/%s/associations/destinations?mount=%s&secret_name=%s",
			client.Address(), t.pathPrefix, t.mount, fmt.Sprintf(secretNameFormat, n)),
		Header: http.Header{
			vaultTokenHeader:     []string{client.Token()},
			vaultNamespaceHeader: []string{client.Namespace()},
		},
	}
	switch t.target {
	case SyncEvents:
		tgt.URL = fmt.Sprintf("%s/v1/%s/data/%s", client.Address(), t.mount, fmt.Sprintf(secretNameFormat, n))
		tgt.Body = []byte(fmt.Sprintf(`{"data": {"foo": "%s"}}`, time.Now().Format(time.RFC3339)))
	case SyncAssociationsWrite:
		tgt.URL = fmt.Sprintf("%s/v1/%s/destinations/%s/%s/associations/set",
			client.Address(), t.pathPrefix, t.config.DestinationType, t.config.DestinationName)
		tgt.Body = []byte(fmt.Sprintf(`{"mount": "%s", "secret_name": "%s"}`, t.mount, fmt.Sprintf(secretNameFormat, n)))
	}
	return tgt
}

func (t *AWSSync) Cleanup(client *api.Client) error {
	// Delete associations
	for i := range t.config.NumAssociations {
		secretName := fmt.Sprintf(secretNameFormat, i)
		t.logger.Debug("deleting association for test secret", "mount", t.mount, "secret", secretName)

		_, err := client.Logical().Write(
			fmt.Sprintf("/%s/destinations/%s/%s/associations/remove", t.pathPrefix, t.config.DestinationType, t.config.DestinationName),
			map[string]any{"mount": t.mount, "secret_name": secretName},
		)
		if err != nil {
			t.logger.Error("failed to clean association", "mount", t.mount, "secret", secretName, "error", err)
		}
	}

	// Delete destination
	t.logger.Debug("deleting destination", "type", t.config.DestinationType, "name", t.config.DestinationName)
	_, err := client.Logical().Delete(
		fmt.Sprintf("/%s/destinations/%s/%s", t.pathPrefix, t.config.DestinationType, t.config.DestinationName),
	)
	if err != nil {
		t.logger.Error("failed to clean destination", "type", t.config.DestinationType, "name", t.config.DestinationName, "error", err)
	}

	// Delete secrets
	for i := range t.config.NumAssociations {
		secretName := fmt.Sprintf(secretNameFormat, i)
		t.logger.Debug("deleting test secret", "mount", t.mount, "secret", secretName)

		err := client.KVv2(t.mount).Delete(context.Background(), fmt.Sprintf(secretNameFormat, i))
		if err != nil {
			t.logger.Error("failed to clean test secret", "mount", t.mount, "secret", secretName, "error", err)
		}
	}

	t.logger.Debug("deleting test engine", "mount", t.mount)
	err = client.Sys().Unmount(t.mount)
	if err != nil {
		t.logger.Error("failed to unmount test engine", "mount", t.mount)
	}

	return nil
}

func (t *AWSSync) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     t.method,
		pathPrefix: t.pathPrefix,
	}
}

func (t *AWSSync) Flags(_ *flag.FlagSet) {}
