// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	IdentityPopulationTestType   = "identity_population"
	IdentityPopulationTestMethod = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[IdentityPopulationTestType] = func() BenchmarkBuilder { return &IdentityPopulation{} }
}

// IdentityPopulation creates a static identity entity dataset during Setup.
// The attack phase is intentionally trivial in this MVP.
type IdentityPopulation struct {
	pathPrefix string
	header     http.Header
	config     *IdentityPopulationConfig
	logger     hclog.Logger

	entityIDs  []string
	authLinker *identityAuthLinkHelper

	count int
}

type IdentityPopulationConfig struct {
	EntityCount      int    `hcl:"entity_count,optional"`
	NamePrefix       string `hcl:"name_prefix,optional"`
	ProgressInterval int    `hcl:"progress_interval,optional"`
	CreateAliases    bool   `hcl:"create_aliases,optional"`
	UserpassMount    string `hcl:"userpass_mount,optional"`
}

func (i *IdentityPopulation) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *IdentityPopulationConfig `hcl:"config,block"`
	}{
		Config: &IdentityPopulationConfig{
			EntityCount:      10000,
			NamePrefix:       "seed-entity",
			ProgressInterval: 1000,
			CreateAliases:    true,
			UserpassMount:    "userpass",
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	i.config = testConfig.Config

	if i.config.EntityCount <= 0 {
		return fmt.Errorf("entity_count must be greater than 0")
	}

	if i.config.ProgressInterval <= 0 {
		return fmt.Errorf("progress_interval must be greater than 0")
	}

	if i.config.NamePrefix == "" {
		return fmt.Errorf("name_prefix cannot be empty")
	}

	if strings.TrimSpace(i.config.UserpassMount) == "" {
		return fmt.Errorf("userpass_mount cannot be empty")
	}

	return nil
}

func (i *IdentityPopulation) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	// Identity is a built-in path, so this target does not create a secret mount.
	// The interface requires this arg for all targets.
	_ = mountName

	i.logger = targetLogger.Named(IdentityPopulationTestType)
	i.pathPrefix = "/v1/sys/health"
	i.header = generateHeader(client)
	i.entityIDs = make([]string, 0, i.config.EntityCount)

	authLinker, err := newIdentityAuthLinkHelper(client, identityAuthLinkConfig{
		CreateAliases: i.config.CreateAliases,
		UserpassMount: i.config.UserpassMount,
		RandomMounts:  topLevelConfig != nil && topLevelConfig.RandomMounts,
	})
	if err != nil {
		return nil, err
	}
	i.authLinker = authLinker

	start := time.Now()
	i.logger.Info("entity population start", "total", i.config.EntityCount)

	for idx := 1; idx <= i.config.EntityCount; idx++ {
		entityName := i.entityName(idx)

		entityPath := filepath.ToSlash("identity/entity/name/" + entityName)
		_, err := client.Logical().Write(entityPath, map[string]any{})
		if err != nil {
			return nil, fmt.Errorf("error creating entity %q: %w", entityName, err)
		}

		// The create-by-name endpoint can return data=nil, so read back to get id.
		readSec, err := client.Logical().Read(entityPath)
		if err != nil {
			return nil, fmt.Errorf("error reading entity %q after create: %w", entityName, err)
		}

		if readSec == nil || readSec.Data == nil {
			return nil, fmt.Errorf("empty response reading entity %q after create", entityName)
		}

		val, ok := readSec.Data["id"]
		if !ok {
			return nil, fmt.Errorf("missing id for entity %q", entityName)
		}

		id, ok := val.(string)
		if !ok || id == "" {
			return nil, fmt.Errorf("invalid id for entity %q", entityName)
		}

		i.entityIDs = append(i.entityIDs, id)

		if err := i.authLinker.createEntityAlias(client, entityName, id); err != nil {
			return nil, err
		}

		i.count = idx

		if idx%i.config.ProgressInterval == 0 || idx == i.config.EntityCount {
			i.logger.Info("entity population", "progress", fmt.Sprintf("%d/%d", idx, i.config.EntityCount))
		}
	}

	i.logger.Info("entity population", "complete", fmt.Sprintf("%d/%d", i.count, i.config.EntityCount), "elapsed", time.Since(start).String())

	return &IdentityPopulation{
		pathPrefix: i.pathPrefix,
		header:     i.header,
		config:     i.config,
		logger:     i.logger,
		entityIDs:  i.entityIDs,
		authLinker: i.authLinker,
		count:      i.count,
	}, nil
}

// Target is intentionally trivial for this MVP; this target's primary value is setup-time population.
func (i *IdentityPopulation) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: IdentityPopulationTestMethod,
		URL:    client.Address() + i.pathPrefix,
		Header: i.header,
	}
}

func (i *IdentityPopulation) Cleanup(client *api.Client) error {
	_ = client
	// TODO: cleanup is intentionally deferred in this MVP.
	return nil
}

func (i *IdentityPopulation) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     IdentityPopulationTestMethod,
		pathPrefix: i.pathPrefix,
	}
}

func (i *IdentityPopulation) Flags(fs *flag.FlagSet) {}

// AliasEntityLinks returns a copy of alias name to entity ID linkages created in setup.
func (i *IdentityPopulation) AliasEntityLinks() map[string]string {
	if i.authLinker == nil {
		return map[string]string{}
	}

	return i.authLinker.aliasEntityLinksCopy()
}

func (i *IdentityPopulation) entityName(idx int) string {
	return fmt.Sprintf("%s-%06d", i.config.NamePrefix, idx)
}
