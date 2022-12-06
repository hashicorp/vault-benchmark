package vegeta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type ldapsecrettest struct {
	pathPrefix string
	header     http.Header
	roleName   string
}

type LDAPSecretConfig struct {
	Username       string `json:"username"`
	DN             string `json:"dn"`
	RotationPeriod string `json:"rotation_period"`
}

func (u *LDAPSecretConfig) FromJSON(path string) error {
	if path == "" {
		return fmt.Errorf("no LDAP user config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(u); err != nil {
		return err
	}

	// Check for required fields
	switch {
	case u.Username == "":
		return fmt.Errorf("no username passed but is required")
	case u.DN == "":
		return fmt.Errorf("no dn passed but is required")
	case u.RotationPeriod == "":
		return fmt.Errorf("no rotation period passed but is required")
	default:
		return nil
	}
}

func (l *ldapsecrettest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + l.pathPrefix + "/static-role/" + l.roleName,
		Header: l.header,
	}
}

func setupLDAPSecret(client *api.Client, randomMounts bool, config *LDAPAuthConfig, roleConfig *LDAPSecretConfig) (*ldapsecrettest, error) {
	ldapPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		ldapPath = "ldap"
	}

	err = client.Sys().Mount(ldapPath, &api.MountInput{
		Type: "ldap",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Write LDAP config
	_, err = client.Logical().Write(ldapPath+"/config", map[string]interface{}{
		"url":                     config.URL,
		"case_sensitive_names":    config.CaseSensitiveNames,
		"request_timeout":         config.RequestTimeout,
		"starttls":                config.StartTLS,
		"tls_min_version":         config.TLSMinVersion,
		"tls_max_version":         config.TLSMaxVersion,
		"insecure_tls":            config.InsecureTLS,
		"certificate":             config.Certificate,
		"client_tls_cert":         config.ClientTLSCert,
		"client_tls_key":          config.ClientTLSKey,
		"binddn":                  config.BindDN,
		"bindpass":                config.BindPass,
		"userdn":                  config.UserDN,
		"userattr":                config.UserAttr,
		"discoverdn":              config.DiscoverDN,
		"deny_null_bind":          config.DenyNullBind,
		"upndomain":               config.UPNDomain,
		"userfilter":              config.UserFilter,
		"anonymous_group_search":  config.AnonymousGroupSearch,
		"group_filter":            config.GroupFilter,
		"groupdn":                 config.GroupDN,
		"groupattr":               config.GroupAttr,
		"username_as_alias":       config.UsernameAsAlias,
		"token_ttl":               config.TokenTTL,
		"token_max_ttl":           config.TokenMaxTTL,
		"token_policies":          config.TokenPolicies,
		"token_bound_cidrs":       config.TokenBoundCIDRs,
		"token_explicit_max_ttl":  config.TokenExplicitMaxTTL,
		"token_no_default_policy": config.TokenNoDefaultPolicy,
		"token_num_uses":          config.TokenNumUses,
		"token_period":            config.TokenPeriod,
		"token_type":              config.TokenType,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(ldapPath+"/static-role/"+roleConfig.Username, map[string]interface{}{
		"dn":              roleConfig.DN,
		"username":        roleConfig.Username,
		"rotation_period": roleConfig.RotationPeriod,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &ldapsecrettest{
		pathPrefix: "/v1/" + ldapPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.Username,
	}, nil
}
