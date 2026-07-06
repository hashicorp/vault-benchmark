// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
)

type identityAuthLinkConfig struct {
	CreateAliases bool
	UserpassMount string
	RandomMounts  bool
}

type identityAuthLinkHelper struct {
	createAliases bool

	userpassMountPath string
	userpassAccessor  string

	aliasIDs        []string
	aliasToEntityID map[string]string
}

func newIdentityAuthLinkHelper(client *api.Client, cfg identityAuthLinkConfig) (*identityAuthLinkHelper, error) {
	helper := &identityAuthLinkHelper{
		createAliases:   cfg.CreateAliases,
		aliasIDs:        make([]string, 0),
		aliasToEntityID: make(map[string]string),
	}

	if !cfg.CreateAliases {
		return helper, nil
	}

	authMountPath := normalizeAuthMountPath(cfg.UserpassMount)
	if cfg.RandomMounts {
		runID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("error generating userpass mount run id: %w", err)
		}
		authMountPath = authMountPath + "-" + runID
	}

	accessor, resolvedMountPath, err := ensureUserpassMountAccessor(client, authMountPath)
	if err != nil {
		return nil, err
	}

	helper.userpassAccessor = accessor
	helper.userpassMountPath = resolvedMountPath

	return helper, nil
}

func (h *identityAuthLinkHelper) createEntityAlias(client *api.Client, aliasName string, entityID string) error {
	if !h.createAliases {
		return nil
	}

	aliasResp, err := client.Logical().Write("identity/entity-alias", map[string]any{
		"name":           aliasName,
		"canonical_id":   entityID,
		"mount_accessor": h.userpassAccessor,
	})
	if err != nil {
		return fmt.Errorf("error creating alias for entity alias name %q: %w", aliasName, err)
	}

	if aliasResp != nil && aliasResp.Data != nil {
		if rawAliasID, ok := aliasResp.Data["id"]; ok {
			if aliasID, ok := rawAliasID.(string); ok && aliasID != "" {
				h.aliasIDs = append(h.aliasIDs, aliasID)
			}
		}
	}

	h.aliasToEntityID[aliasName] = entityID
	return nil
}

func (h *identityAuthLinkHelper) aliasEntityLinksCopy() map[string]string {
	links := make(map[string]string, len(h.aliasToEntityID))
	for alias, entityID := range h.aliasToEntityID {
		links[alias] = entityID
	}

	return links
}

func ensureUserpassMountAccessor(client *api.Client, mountPath string) (string, string, error) {
	authMountPath := normalizeAuthMountPath(mountPath)
	authMountKey := authMountPath + "/"

	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		return "", "", fmt.Errorf("error listing auth mounts: %w", err)
	}

	if authMount, ok := authMounts[authMountKey]; ok {
		if authMount.Type != "userpass" {
			return "", "", fmt.Errorf("auth mount %q exists with type %q, expected userpass", authMountPath, authMount.Type)
		}

		if authMount.Accessor == "" {
			return "", "", fmt.Errorf("auth mount %q has empty accessor", authMountPath)
		}

		return authMount.Accessor, authMountPath, nil
	}

	if err := client.Sys().EnableAuthWithOptions(authMountPath, &api.EnableAuthOptions{Type: "userpass"}); err != nil {
		return "", "", fmt.Errorf("error enabling userpass auth mount %q: %w", authMountPath, err)
	}

	authMounts, err = client.Sys().ListAuth()
	if err != nil {
		return "", "", fmt.Errorf("error listing auth mounts after enabling %q: %w", authMountPath, err)
	}

	authMount, ok := authMounts[authMountKey]
	if !ok {
		return "", "", fmt.Errorf("auth mount %q not found after enable", authMountPath)
	}

	if authMount.Accessor == "" {
		return "", "", fmt.Errorf("auth mount %q has empty accessor after enable", authMountPath)
	}

	return authMount.Accessor, authMountPath, nil
}

func normalizeAuthMountPath(path string) string {
	normalized := strings.Trim(path, "/")
	if normalized == "" {
		return "userpass"
	}

	return normalized
}
