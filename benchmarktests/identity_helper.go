// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/hashicorp/vault/api"
)

const userpassMountBase = "userpass"

func userpassMountPath(runID string) string {
	return userpassMountBase + "-" + runID
}

func objectName(mountName, typ, runID string, idx int) string {
	return mountName + "-" + typ + "-" + runID + "-" + strconv.Itoa(idx)
}

// Slot 0 is the login mount (username == alias name); slots 1..N are bloat-only.
func userpassSlotMountPath(runID string, slot int) string {
	if slot == 0 {
		return userpassMountBase + "-" + runID
	}
	return userpassMountBase + "-" + runID + "-" + strconv.Itoa(slot)
}

func enableUserpassMounts(client *api.Client, runID string, count int) ([]string, error) {
	accessors := make([]string, count)
	for slot := range count {
		mountPath := userpassSlotMountPath(runID, slot)
		if err := client.Sys().EnableAuthWithOptions(mountPath, &api.EnableAuthOptions{Type: "userpass"}); err != nil {
			return nil, fmt.Errorf("error enabling userpass auth mount %q: %w", mountPath, err)
		}
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		return nil, fmt.Errorf("error listing auth mounts: %w", err)
	}
	for slot := range count {
		mountPath := userpassSlotMountPath(runID, slot)
		mount, ok := mounts[mountPath+"/"]
		if !ok {
			return nil, fmt.Errorf("auth mount %q not found after enable", mountPath)
		}
		if mount.Accessor == "" {
			return nil, fmt.Errorf("auth mount %q has empty accessor after enable", mountPath)
		}
		accessors[slot] = mount.Accessor
	}
	return accessors, nil
}

func addEntityAlias(client *api.Client, accessor, name, entityID string) error {
	_, err := client.Logical().Write("identity/entity-alias", map[string]any{
		"name":           name,
		"canonical_id":   entityID,
		"mount_accessor": accessor,
	})
	if err != nil {
		return fmt.Errorf("error creating entity alias %q: %w", name, err)
	}
	return nil
}

func addUserpassUser(client *api.Client, mountPath, name string) error {
	userPath := filepath.ToSlash(filepath.Join("auth", mountPath, "users", name)) // ToSlash for Windows
	_, err := client.Logical().Write(userPath, map[string]any{
		"password": identityPassword,
	})
	if err != nil {
		return fmt.Errorf("error creating userpass user %q: %w", name, err)
	}
	return nil
}

func validateLogin(client *api.Client, mountPath, name, expectedEntityID string) error {
	loginPath := filepath.ToSlash(filepath.Join("auth", mountPath, "login", name))
	secret, err := client.Logical().Write(loginPath, map[string]any{
		"password": identityPassword,
	})
	if err != nil {
		return fmt.Errorf("login resolution check failed for user %q: %w", name, err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("login resolution check for user %q returned no auth data", name)
	}

	if secret.Auth.EntityID != expectedEntityID {
		return fmt.Errorf("login for user %q resolved to entity %q, expected %q",
			name, secret.Auth.EntityID, expectedEntityID)
	}

	return nil
}

func idFromResponse(resp *api.Secret) (string, error) {
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

// Wraparound so membership is deterministic across any entity count.
// Returns a sub-slice when the window fits without wrapping (zero copy).
func selectGroupMembers(entityIDs []string, groupIndex, groupSize int) []string {
	n := len(entityIDs)
	start := (groupIndex * groupSize) % n
	if start+groupSize <= n {
		return entityIDs[start : start+groupSize]
	}
	members := make([]string, 0, groupSize)
	for offset := range groupSize {
		members = append(members, entityIDs[(start+offset)%n])
	}
	return members
}

// Wraparound so assignment is deterministic across any policy count.
// Returns a sub-slice when the window fits without wrapping (zero copy).
func selectPolicyNames(policyNames []string, entityIndex, polSize int) []string {
	n := len(policyNames)
	start := (entityIndex * polSize) % n
	if start+polSize <= n {
		return policyNames[start : start+polSize]
	}
	selected := make([]string, 0, polSize)
	for offset := range polSize {
		selected = append(selected, policyNames[(start+offset)%n])
	}
	return selected
}

// parseGroups preset semantics:
//
//	balanced (default): ~entity_count/group_count members per group
//	empty             : no members
//	full              : all entities in every group
//	count+size        : count groups get size members, the rest empty
func parseGroups(g *GroupConfig, groupCount, entityCount int) (filled, size int, err error) {
	if groupCount <= 0 {
		return 0, 0, nil
	}
	if g == nil {
		return groupCount, ceilDiv(entityCount, groupCount), nil
	}

	if g.Count > 0 || g.Size > 0 {
		if g.Preset != "" {
			return 0, 0, fmt.Errorf("groups: set either preset or count+size, not both")
		}
		if g.Count < 0 || g.Count > groupCount {
			return 0, 0, fmt.Errorf("groups.count (%d) must be in [0, group_count=%d]", g.Count, groupCount)
		}
		if g.Size < 0 || g.Size > entityCount {
			return 0, 0, fmt.Errorf("groups.size (%d) must be in [0, entity_count=%d]", g.Size, entityCount)
		}
		return g.Count, g.Size, nil
	}

	switch g.Preset {
	case "", "balanced":
		return groupCount, ceilDiv(entityCount, groupCount), nil
	case "empty":
		return 0, 0, nil
	case "full":
		return groupCount, entityCount, nil
	default:
		return 0, 0, fmt.Errorf("invalid groups preset %q: must be \"balanced\", \"empty\", or \"full\"", g.Preset)
	}
}

// parseAliases preset semantics:
//
//	balanced (default): ~alias_count/entity_count aliases per entity
//	empty             : no aliases
//	full              : alias_count aliases on every entity
//	count+size        : count entities get size aliases, the rest empty
func parseAliases(a *AliasesConfig, aliasCount, entityCount int) (filled, size int, err error) {
	if aliasCount <= 0 {
		return 0, 0, nil
	}
	if a == nil {
		return entityCount, ceilDiv(aliasCount, entityCount), nil
	}

	if a.Count > 0 || a.Size > 0 {
		if a.Preset != "" {
			return 0, 0, fmt.Errorf("aliases: set either preset or count+size, not both")
		}
		if a.Count < 0 || a.Count > entityCount {
			return 0, 0, fmt.Errorf("aliases.count (%d) must be in [0, entity_count=%d]", a.Count, entityCount)
		}
		if a.Size < 0 || a.Size > aliasCount {
			return 0, 0, fmt.Errorf("aliases.size (%d) must be in [0, alias_count=%d]", a.Size, aliasCount)
		}
		return a.Count, a.Size, nil
	}

	switch a.Preset {
	case "", "balanced":
		return entityCount, ceilDiv(aliasCount, entityCount), nil
	case "empty":
		return 0, 0, nil
	case "full":
		return entityCount, aliasCount, nil
	default:
		return 0, 0, fmt.Errorf("invalid aliases preset %q: must be \"balanced\", \"empty\", or \"full\"", a.Preset)
	}
}

// parsePolicies preset semantics:
//
//	balanced (default): ~policy_count/entity_count policies per entity
//	empty             : no policies
//	full              : policy_count policies on every entity
//	count+size        : count entities get size policies, the rest empty
func parsePolicies(p *PoliciesConfig, policyCount, entityCount int) (filled, size int, err error) {
	if policyCount <= 0 {
		return 0, 0, nil
	}
	if p == nil {
		return entityCount, ceilDiv(policyCount, entityCount), nil
	}

	if p.Count > 0 || p.Size > 0 {
		if p.Preset != "" {
			return 0, 0, fmt.Errorf("policies: set either preset or count+size, not both")
		}
		if p.Count < 0 || p.Count > entityCount {
			return 0, 0, fmt.Errorf("policies.count (%d) must be in [0, entity_count=%d]", p.Count, entityCount)
		}
		if p.Size < 0 || p.Size > policyCount {
			return 0, 0, fmt.Errorf("policies.size (%d) must be in [0, policy_count=%d]", p.Size, policyCount)
		}
		return p.Count, p.Size, nil
	}

	switch p.Preset {
	case "", "balanced":
		return entityCount, ceilDiv(policyCount, entityCount), nil
	case "empty":
		return 0, 0, nil
	case "full":
		return entityCount, policyCount, nil
	default:
		return 0, 0, fmt.Errorf("invalid policies preset %q: must be \"balanced\", \"empty\", or \"full\"", p.Preset)
	}
}

func configureAttack(cfg *IdentityConfig, runID string) (method, pathPrefix string) {
	switch cfg.Workload {
	case identityWorkloadLogin:
		return http.MethodPost, "/v1/" + filepath.ToSlash(filepath.Join("auth", userpassMountPath(runID)))
	case identityWorkloadGroupRead:
		return http.MethodGet, "/v1/identity/group/id/"
	default: // identityWorkloadPopulate
		return http.MethodGet, identityNoWorkloadPath
	}
}

