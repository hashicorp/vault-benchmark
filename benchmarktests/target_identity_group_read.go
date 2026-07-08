// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	IdentityGroupReadTestType   = "identity_group_read"
	IdentityGroupReadTestMethod = "GET"
)

func init() {
	TestList[IdentityGroupReadTestType] = func() BenchmarkBuilder { return &IdentityGroupRead{} }
}

type IdentityGroupRead struct {
	pathPrefix string
	header     http.Header
	config     *IdentityGroupReadConfig
	groupIDs   []string
	entityIDs  []string
	logger     hclog.Logger
}

type IdentityGroupReadConfig struct {
	EntityCount   int    `hcl:"entity_count,optional"`
	GroupCount    int    `hcl:"group_count,optional"`
	GroupSize     int    `hcl:"group_size,optional"`
	CreateAliases bool   `hcl:"create_aliases,optional"`
	UserpassMount string `hcl:"userpass_mount,optional"`
}

func (i *IdentityGroupRead) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *IdentityGroupReadConfig `hcl:"config,block"`
	}{
		Config: &IdentityGroupReadConfig{
			EntityCount:   1000,
			GroupCount:    1000,
			GroupSize:     10,
			CreateAliases: true,
			UserpassMount: "userpass",
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	if testConfig.Config.EntityCount <= 0 {
		return fmt.Errorf("entity_count must be greater than 0")
	}
	if testConfig.Config.GroupCount <= 0 {
		return fmt.Errorf("group_count must be greater than 0")
	}
	if testConfig.Config.GroupSize <= 0 {
		return fmt.Errorf("group_size must be greater than 0")
	}
	if testConfig.Config.GroupSize > testConfig.Config.EntityCount {
		return fmt.Errorf("group_size (%d) cannot be greater than entity_count (%d)", testConfig.Config.GroupSize, testConfig.Config.EntityCount)
	}
	if testConfig.Config.CreateAliases && testConfig.Config.UserpassMount == "" {
		return fmt.Errorf("userpass_mount cannot be empty when create_aliases is true")
	}

	i.config = testConfig.Config
	return nil
}

func (i *IdentityGroupRead) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	i.logger = targetLogger.Named(IdentityGroupReadTestType)
	runID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate run id: %v", err)
	}

	entityIDs := make([]string, 0, i.config.EntityCount)
	groupIDs := make([]string, 0, i.config.GroupCount)
	// When create_aliases is set, aliases are validated at setup via a
	// single-sample login probe (below); note the read workload itself does not
	// exercise aliases. Whether create_aliases belongs here long-term is the
	// deferred dataset-vs-workload question.
	authLinker, err := newIdentityAuthLinkHelper(client, identityAuthLinkConfig{
		CreateAliases: i.config.CreateAliases,
		UserpassMount: i.config.UserpassMount,
		RandomMounts:  topLevelConfig != nil && topLevelConfig.RandomMounts,
	})
	if err != nil {
		return nil, err
	}

	firstEntityName := ""
	for idx := 0; idx < i.config.EntityCount; idx++ {
		entityName := mountName + "-entity-" + runID + "-" + strconv.Itoa(idx)
		if idx == 0 {
			firstEntityName = entityName
		}
		resp, err := client.Logical().Write("identity/entity", map[string]interface{}{
			"name": entityName,
		})
		if err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs)
			return nil, fmt.Errorf("error creating identity entity %q: %v", entityName, err)
		}

		entityID, err := identityIDFromResponse(resp)
		if err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs)
			return nil, fmt.Errorf("error reading identity entity id for %q: %v", entityName, err)
		}

		entityIDs = append(entityIDs, entityID)

		err = authLinker.linkEntityAuth(client, entityName, entityID)
		if err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs)
			return nil, err
		}
	}

	if i.config.CreateAliases && len(entityIDs) > 0 {
		if err := authLinker.validateLoginResolution(client, firstEntityName, entityIDs[0]); err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs)
			return nil, err
		}
		i.logger.Info("login resolution validated", "user", firstEntityName, "entity_id", entityIDs[0])
	}

	for idx := 0; idx < i.config.GroupCount; idx++ {
		groupName := mountName + "-group-" + runID + "-" + strconv.Itoa(idx)
		members := selectGroupMembers(entityIDs, idx, i.config.GroupSize)

		resp, err := client.Logical().Write("identity/group", map[string]interface{}{
			"name":              groupName,
			"type":              "internal",
			"member_entity_ids": members,
		})
		if err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs)
			return nil, fmt.Errorf("error creating identity group %q: %v", groupName, err)
		}

		groupID, err := identityIDFromResponse(resp)
		if err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs)
			return nil, fmt.Errorf("error reading identity group id for %q: %v", groupName, err)
		}

		groupIDs = append(groupIDs, groupID)
	}

	return &IdentityGroupRead{
		pathPrefix: "/v1/identity/group/id/",
		header:     generateHeader(client),
		config:     i.config,
		groupIDs:   groupIDs,
		entityIDs:  entityIDs,
		logger:     i.logger,
	}, nil
}

func (i *IdentityGroupRead) Target(client *api.Client) vegeta.Target {
	if len(i.groupIDs) == 0 {
		return vegeta.Target{
			Method: IdentityGroupReadTestMethod,
			URL:    client.Address() + "/v1/identity/group/id/",
			Header: i.header,
		}
	}

	groupID := i.groupIDs[rand.Intn(len(i.groupIDs))]
	return vegeta.Target{
		Method: IdentityGroupReadTestMethod,
		URL:    client.Address() + "/v1/identity/group/id/" + groupID,
		Header: i.header,
	}
}

func (i *IdentityGroupRead) Cleanup(client *api.Client) error {
	i.logger.Trace("cleaning up identity benchmark resources")
	return i.cleanupCreatedIdentityResources(client, i.groupIDs, i.entityIDs)
}

func (i *IdentityGroupRead) Flags(fs *flag.FlagSet) {}

func (i *IdentityGroupRead) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     IdentityGroupReadTestMethod,
		pathPrefix: i.pathPrefix,
	}
}

func (i *IdentityGroupRead) cleanupCreatedIdentityResources(client *api.Client, groupIDs []string, entityIDs []string) error {
	var firstErr error

	for _, groupID := range groupIDs {
		_, err := client.Logical().Delete("identity/group/id/" + groupID)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("error deleting identity group %q: %v", groupID, err)
		}
	}

	for _, entityID := range entityIDs {
		_, err := client.Logical().Delete("identity/entity/id/" + entityID)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("error deleting identity entity %q: %v", entityID, err)
		}
	}

	return firstErr
}

func identityIDFromResponse(resp *api.Secret) (string, error) {
	if resp == nil || resp.Data == nil {
		return "", fmt.Errorf("empty response data")
	}

	rawID, ok := resp.Data["id"]
	if !ok {
		return "", fmt.Errorf("response missing id field")
	}

	id, ok := rawID.(string)
	if !ok || id == "" {
		return "", fmt.Errorf("response id is not a non-empty string")
	}

	return id, nil
}

func selectGroupMembers(entityIDs []string, groupIndex int, groupSize int) []string {
	members := make([]string, 0, groupSize)
	start := (groupIndex * groupSize) % len(entityIDs)

	for offset := 0; offset < groupSize; offset++ {
		members = append(members, entityIDs[(start+offset)%len(entityIDs)])
	}

	return members
}
