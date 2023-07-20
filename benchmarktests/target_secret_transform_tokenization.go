// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	TransformTokenizationTestType   = "transform_tokenization"
	TransformTokenizationTestMethod = "POST"
	TransformStoreUsernameEnvVar    = VaultBenchmarkEnvVarPrefix + "TRANSIT_STORE_USERNAME"
	TransformStorePasswordEnvVar    = VaultBenchmarkEnvVarPrefix + "TRANSIT_STORE_PASSWORD"
)

func init() {
	TestList[TransformTokenizationTestType] = func() BenchmarkBuilder {
		return &TransformTokenizationTest{}
	}
}

type TransformTokenizationTest struct {
	pathPrefix string
	header     http.Header
	body       []byte
	roleName   string
	config     *TransformTokenizationTestConfig
	logger     hclog.Logger
}

type TransformTokenizationTestConfig struct {
	StoreConfig        *TransformStoreConfig        `hcl:"store,block"`
	StoreSchemaConfig  *TransformStoreSchemaConfig  `hcl:"store_schema,block"`
	RoleConfig         *TransformRoleConfig         `hcl:"role,block"`
	TokenizationConfig *TransformTokenizationConfig `hcl:"tokenization,block"`
	InputConfig        *TransformInputConfig        `hcl:"input,block"`
}

type TransformStoreConfig struct {
	Name                     string   `hcl:"name"`
	Type                     string   `hcl:"type"`
	Driver                   string   `hcl:"driver"`
	ConnectionString         string   `hcl:"connection_string"`
	Username                 string   `hcl:"username"`
	Password                 string   `hcl:"password"`
	SupportedTransformations []string `hcl:"supported_transformations,optional"`
	Schema                   string   `hcl:"schema,optional"`
	MaxOpenConnections       int      `hcl:"max_open_connections,optional"`
	MaxIdleConnections       int      `hcl:"max_idle_connections,optional"`
	MaxConnectionLifetime    string   `hcl:"max_connection_lifetime,optional"`
}

type TransformStoreSchemaConfig struct {
	Name               string `hcl:"name,optional"`
	Username           string `hcl:"username,optional"`
	Password           string `hcl:"password,optional"`
	TransformationType string `hcl:"transformation_type,optional"`
}

type TransformRoleConfig struct {
	Name            string   `hcl:"name,optional"`
	Transformations []string `hcl:"transformations,optional"`
}

type TransformTokenizationConfig struct {
	Name            string   `hcl:"name,optional"`
	MappingMode     string   `hcl:"mapping_mode,optional"`
	Convergent      bool     `hcl:"convergent,optional"`
	MaxTTL          string   `hcl:"max_ttl,optional"`
	AllowedRoles    []string `hcl:"allowed_roles,optional"`
	Stores          []string `hcl:"stores,optional"`
	DeletionAllowed bool     `hcl:"deletion_allowed,optional"`
}

type TransformInputConfig struct {
	Value          string        `hcl:"value,optional"`
	Transformation string        `hcl:"transformation,optional"`
	TTL            string        `hcl:"ttl,optional"`
	Metadata       string        `hcl:"metadata,optional"`
	Tweak          string        `hcl:"tweak,optional"`
	Reference      string        `hcl:"reference,optional"`
	BatchInput     []interface{} `hcl:"batch_input,optional"`
}

func (t *TransformTokenizationTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *TransformTokenizationTestConfig `hcl:"config,block"`
	}{
		Config: &TransformTokenizationTestConfig{
			RoleConfig: &TransformRoleConfig{
				Name:            "benchmark-role",
				Transformations: []string{"benchmarktransformation"},
			},
			TokenizationConfig: &TransformTokenizationConfig{
				Name:         "benchmarktransformation",
				AllowedRoles: []string{"benchmark-role"},
			},
			InputConfig: &TransformInputConfig{
				Transformation: "benchmarktransformation",
				Value:          "123456789",
			},
			StoreConfig: &TransformStoreConfig{
				Username: os.Getenv(TransformStoreUsernameEnvVar),
				Password: os.Getenv(TransformStorePasswordEnvVar),
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	t.config = testConfig.Config

	return nil
}

func (t *TransformTokenizationTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: TransformTokenizationTestMethod,
		URL:    client.Address() + t.pathPrefix + "/encode/" + t.roleName,
		Body:   t.body,
		Header: t.header,
	}
}

func (t *TransformTokenizationTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     TransformTokenizationTestMethod,
		pathPrefix: t.pathPrefix,
	}
}

func (t *TransformTokenizationTest) Cleanup(client *api.Client) error {
	t.logger.Trace(cleanupLogMessage(t.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(t.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (t *TransformTokenizationTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	t.logger = targetLogger.Named(TransformTokenizationTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Transform mount
	t.logger.Trace(mountLogMessage("secrets", "transform", secretPath))
	err = topLevelConfig.Client.Sys().Mount(secretPath, &api.MountInput{
		Type: "transform",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting transform secrets engine: %v", err)
	}

	setupLogger := t.logger.Named(secretPath)

	// Create Store config if provided
	if t.config.StoreConfig.Type != "" {
		setupLogger.Trace("configuring store")

		// Decode Store config struct to mapstructure to pass with request
		setupLogger.Trace(parsingConfigLogMessage("store"))
		storeConfigData, err := structToMap(t.config.StoreConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing store config from struct: %v", err)
		}

		// Setup store
		setupLogger.Trace(writingLogMessage("store config"), "name", t.config.StoreConfig.Name)
		storePath := filepath.Join(secretPath, "stores", t.config.StoreConfig.Name)
		_, err = topLevelConfig.Client.Logical().Write(storePath, storeConfigData)
		if err != nil {
			return nil, fmt.Errorf("error writing store config %q: %v", t.config.StoreConfig.Name, err)
		}

		if t.config.StoreSchemaConfig != nil {
			setupLogger.Trace("configuring store schema")

			// Decode Store config struct to mapstructure to pass with request
			setupLogger.Trace(parsingConfigLogMessage("store schema"))
			storeSchemaConfigData, err := structToMap(t.config.StoreSchemaConfig)
			if err != nil {
				return nil, fmt.Errorf("error parsing store schema config from struct: %v", err)
			}

			// Setup store
			setupLogger.Trace(writingLogMessage("store schema"), "store", t.config.StoreSchemaConfig.Name)
			storeSchemaPath := filepath.Join(secretPath, "stores", t.config.StoreSchemaConfig.Name, "schema")
			_, err = topLevelConfig.Client.Logical().Write(storeSchemaPath, storeSchemaConfigData)
			if err != nil {
				return nil, fmt.Errorf("error writing store schema %q: %v", t.config.StoreSchemaConfig.Name, err)
			}
		}
	}

	// Decode Role data
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleConfigData, err := structToMap(t.config.RoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("role"), "name", t.config.RoleConfig.Name)
	rolePath := filepath.Join(secretPath, "role", t.config.RoleConfig.Name)
	_, err = topLevelConfig.Client.Logical().Write(rolePath, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing role %q: %v", t.config.RoleConfig.Name, err)
	}

	// Decode Tokenization Transformation data
	setupLogger.Trace("decoding tokenization config data")
	tokenizationConfigData, err := structToMap(t.config.TokenizationConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding tokenization config from struct: %v", err)
	}

	// Create Transformation
	setupLogger.Trace(writingLogMessage("tokenization transformation"), "name", t.config.TokenizationConfig.Name)
	transformationPath := filepath.Join(secretPath, "transformations", "tokenization", t.config.TokenizationConfig.Name)
	_, err = topLevelConfig.Client.Logical().Write(transformationPath, tokenizationConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing tokenization transformation %q: %v", t.config.TokenizationConfig.Name, err)
	}

	// Decode test data to be transformed
	setupLogger.Trace("parsing test transformation input data")
	testData, err := structToMap(t.config.InputConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing test transformation input data from struct: %v", err)
	}

	testDataString, err := json.Marshal(testData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling test encode data: %v", err)
	}

	return &TransformTokenizationTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(topLevelConfig.Client),
		body:       []byte(testDataString),
		roleName:   t.config.RoleConfig.Name,
		logger:     t.logger,
	}, nil
}

func (t *TransformTokenizationTest) Flags(fs *flag.FlagSet) {}
