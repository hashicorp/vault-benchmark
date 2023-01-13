package vegeta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

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
	BindDN         string `json:"binddn"`
	BindPass       string `json:"bindpass"`
	URL            string `json:"url"`
	PasswordPolicy string `json:"password_policy"`
	Schema         string `json:"schema"`
	UserDN         string `json:"userdn"`
	UserAttr       string `json:"userattr"`
	UPNDomain      string `json:"upndomain"`
	RequestTimeout int    `json:"request_timeout"`
	StartTLS       bool   `json:"starttls"`
	InsecureTLS    bool   `json:"insecure_tls"`
	Certificate    string `json:"certificate"`
	ClientTLSCert  string `json:"client_tls_cert"`
	ClientTLSKey   string `json:"client_tls_key"`
}

type LDAPStaticRoleConfig struct {
	Username       string `json:"username"`
	DN             string `json:"dn"`
	RotationPeriod string `json:"rotation_period"`
}

type LDAPDynamicRoleConfig struct {
	RoleName         string `json:"role_name"`
	CreationLDIF     string `json:"creation_ldif"`
	DeletionLDIF     string `json:"deletion_ldif"`
	RollbackLDIF     string `json:"rollback_ldif"`
	UsernameTemplate string `json:"username_template"`
	DefaultTTL       int    `json:"default_ttl"`
	MaxTTL           int    `json:"max_ttl"`
}

func (c *LDAPSecretConfig) FromJSON(path string) error {
	// Set Defaults
	c.Schema = "openldap"
	c.RequestTimeout = 90

	if path == "" {
		return fmt.Errorf("no LDAP Config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(c); err != nil {
		return err
	}

	// Check for required fields
	switch {
	case c.BindDN == "":
		return fmt.Errorf("no BindDN provided but is required")
	case c.BindPass == "":
		return fmt.Errorf("no BindPass provided but is required")
	default:
		return nil
	}
}

func (u *LDAPStaticRoleConfig) FromJSON(path string) error {
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
	case u.RotationPeriod == "":
		return fmt.Errorf("no rotation period passed but is required")
	default:
		return nil
	}
}

func (u *LDAPDynamicRoleConfig) FromJSON(path string) error {
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
	case u.RoleName == "":
		return fmt.Errorf("no role name passed but is required")
	case u.CreationLDIF == "":
		return fmt.Errorf("no creation ldif passed but is required")
	case u.DeletionLDIF == "":
		return fmt.Errorf("no deletion ldif passed but is required")
	default:
		return nil
	}
}

func (l *ldapsecrettest) readStatic(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + l.pathPrefix + "/static-role/" + l.roleName,
		Header: l.header,
	}
}

func (l *ldapsecrettest) rotateStatic(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + l.pathPrefix + "/rotate-role/" + l.roleName,
		Header: l.header,
	}
}

func (l *ldapsecrettest) readDynamic(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + l.pathPrefix + "/creds/" + l.roleName,
		Header: l.header,
	}
}

func (l *ldapsecrettest) cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(l.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupLDAPStaticSecret(client *api.Client, randomMounts bool, config *LDAPSecretConfig, roleConfig *LDAPStaticRoleConfig) (*ldapsecrettest, error) {
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
		return nil, fmt.Errorf("error mounting LDAP: %v", err)
	}

	// Write LDAP config
	_, err = client.Logical().Write(ldapPath+"/config", map[string]interface{}{
		"binddn":          config.BindDN,
		"bindpass":        config.BindPass,
		"url":             config.URL,
		"password_policy": config.PasswordPolicy,
		"schema":          config.Schema,
		"userdn":          config.UserDN,
		"userattr":        config.UserAttr,
		"upndomain":       config.UPNDomain,
		"request_timeout": config.RequestTimeout,
		"starttls":        config.StartTLS,
		"insecure_tls":    config.InsecureTLS,
		"certificate":     config.Certificate,
		"client_tls_cert": config.ClientTLSCert,
		"client_tls_key":  config.ClientTLSKey,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing LDAP config: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(ldapPath+"/static-role/"+roleConfig.Username, map[string]interface{}{
		"dn":              roleConfig.DN,
		"username":        roleConfig.Username,
		"rotation_period": roleConfig.RotationPeriod,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing LDAP role: %v", err)
	}

	return &ldapsecrettest{
		pathPrefix: "/v1/" + ldapPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.Username,
	}, nil
}

func setupLDAPDynamicSecret(client *api.Client, randomMounts bool, config *LDAPSecretConfig, roleConfig *LDAPDynamicRoleConfig) (*ldapsecrettest, error) {
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
		return nil, fmt.Errorf("error mounting LDAP: %v", err)
	}

	// Write LDAP config
	_, err = client.Logical().Write(ldapPath+"/config", map[string]interface{}{
		"binddn":          config.BindDN,
		"bindpass":        config.BindPass,
		"url":             config.URL,
		"password_policy": config.PasswordPolicy,
		"schema":          config.Schema,
		"userdn":          config.UserDN,
		"userattr":        config.UserAttr,
		"upndomain":       config.UPNDomain,
		"request_timeout": config.RequestTimeout,
		"starttls":        config.StartTLS,
		"insecure_tls":    config.InsecureTLS,
		"certificate":     config.Certificate,
		"client_tls_cert": config.ClientTLSCert,
		"client_tls_key":  config.ClientTLSKey,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing LDAP config: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(ldapPath+"/role/"+roleConfig.RoleName, map[string]interface{}{
		"role_name":         roleConfig.RoleName,
		"creation_ldif":     roleConfig.CreationLDIF,
		"deletion_ldif":     roleConfig.DeletionLDIF,
		"rollback_ldif":     roleConfig.RollbackLDIF,
		"username_template": roleConfig.UsernameTemplate,
		"default_ttl":       roleConfig.DefaultTTL,
		"max_ttl":           roleConfig.MaxTTL,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing LDAP role: %v", err)
	}

	return &ldapsecrettest{
		pathPrefix: "/v1/" + ldapPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.RoleName,
	}, nil
}
