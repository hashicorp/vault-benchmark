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

// TODO(refactor-pr):
//   - rename cleanupCreatedIdentityResources -> cleanupIdentityResources
//   - rename script/struct to a generalist weighted identity-lifecycle target
//   - add package/target docs
//   - clean up Setup: extract create/validate phases + single deferred rollback
//     (mirror target_identity_population)
//   - move identityIDFromResponse into the helper
//   shared with identity_population:
//   - parallelize entity creation with a bounded worker pool (setup is serial)
//   - allow cleanup with deterministic mounts (identity cleanup never deletes the
//     userpass mount, unlike the global run.go:280 guard assumes)
//   - consolidate with identity_population once renamed

type IdentityGroupRead struct {
	pathPrefix    string
	header        http.Header
	config        *IdentityGroupReadConfig
	groupIDs      []string
	entityIDs     []string
	probeUsers    []string
	userpassMount string
	logger        hclog.Logger
}

type IdentityGroupReadConfig struct {
	EntityCount       int    `hcl:"entity_count,optional"`
	GroupCount        int    `hcl:"group_count,optional"`
	GroupSize         int    `hcl:"group_size,optional"`
	CreateAliases     bool   `hcl:"create_aliases,optional"`
	UserpassMount     string `hcl:"userpass_mount,optional"`
	ValidationSamples int    `hcl:"validation_samples,optional"`
}

func (i *IdentityGroupRead) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *IdentityGroupReadConfig `hcl:"config,block"`
	}{
		Config: &IdentityGroupReadConfig{
			EntityCount:       1000,
			GroupCount:        1000,
			GroupSize:         10,
			CreateAliases:     true,
			UserpassMount:     "userpass",
			ValidationSamples: identityValidationSamples,
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
	if testConfig.Config.ValidationSamples <= 0 {
		return fmt.Errorf("validation_samples must be greater than 0")
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
	entityNames := make([]string, 0, i.config.EntityCount)
	groupIDs := make([]string, 0, i.config.GroupCount)
	var probeUsers []string
	// When create_aliases is set, each entity is linked to a userpass alias and a
	// sample of those links is validated by login below.
	authLinker, err := newIdentityAuthLinkHelper(client, identityAuthLinkConfig{
		CreateAliases: i.config.CreateAliases,
		UserpassMount: i.config.UserpassMount,
		RandomMounts:  topLevelConfig != nil && topLevelConfig.RandomMounts,
	})
	if err != nil {
		return nil, err
	}
	userpassMount := authLinker.mountPath()

	for idx := 0; idx < i.config.EntityCount; idx++ {
		entityName := mountName + "-entity-" + runID + "-" + strconv.Itoa(idx)
		resp, err := client.Logical().Write("identity/entity", map[string]interface{}{
			"name": entityName,
		})
		if err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, probeUsers, userpassMount)
			return nil, fmt.Errorf("error creating identity entity %q: %v", entityName, err)
		}

		entityID, err := identityIDFromResponse(resp)
		if err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, probeUsers, userpassMount)
			return nil, fmt.Errorf("error reading identity entity id for %q: %v", entityName, err)
		}

		entityIDs = append(entityIDs, entityID)
		entityNames = append(entityNames, entityName)

		err = authLinker.linkEntity(client, entityName, entityID)
		if err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, probeUsers, userpassMount)
			return nil, err
		}
	}

	if i.config.CreateAliases && len(entityIDs) > 0 {
		// A bare userpass login always resolves to some entity, so each sample
		// checks against its expected id to confirm the alias mapping. Alias-only
		// mode has no users to log in as, so validateLogin creates a throwaway
		// probe user per sample; track them so Cleanup can remove them.
		sampleCount := min(i.config.ValidationSamples, len(entityIDs))

		for _, idx := range sampleIndices(len(entityIDs), sampleCount) {
			name := entityNames[idx-1]
			probeUsers = append(probeUsers, name)
			if err := authLinker.validateLogin(client, name, entityIDs[idx-1]); err != nil {
				_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, probeUsers, userpassMount)
				return nil, err
			}
		}
		i.logger.Info("login resolution validated", "samples", sampleCount, "entities", len(entityIDs))
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
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, probeUsers, userpassMount)
			return nil, fmt.Errorf("error creating identity group %q: %v", groupName, err)
		}

		groupID, err := identityIDFromResponse(resp)
		if err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, probeUsers, userpassMount)
			return nil, fmt.Errorf("error reading identity group id for %q: %v", groupName, err)
		}

		groupIDs = append(groupIDs, groupID)
	}

	return &IdentityGroupRead{
		pathPrefix:    "/v1/identity/group/id/",
		header:        generateHeader(client),
		config:        i.config,
		groupIDs:      groupIDs,
		entityIDs:     entityIDs,
		probeUsers:    probeUsers,
		userpassMount: userpassMount,
		logger:        i.logger,
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
	return i.cleanupCreatedIdentityResources(client, i.groupIDs, i.entityIDs, i.probeUsers, i.userpassMount)
}

func (i *IdentityGroupRead) Flags(fs *flag.FlagSet) {}

func (i *IdentityGroupRead) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     IdentityGroupReadTestMethod,
		pathPrefix: i.pathPrefix,
	}
}

func (i *IdentityGroupRead) cleanupCreatedIdentityResources(client *api.Client, groupIDs []string, entityIDs []string, probeUsers []string, userpassMount string) error {
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

	for _, user := range probeUsers {
		_, err := client.Logical().Delete("auth/" + userpassMount + "/users/" + user)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("error deleting validation user %q: %v", user, err)
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
