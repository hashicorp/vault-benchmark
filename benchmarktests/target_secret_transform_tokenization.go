package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
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
	config     *TransformTestConfig
	logger     hclog.Logger
}

type TransformTestConfig struct {
	Config *TransformTokenizationTestConfig `hcl:"config,block"`
}

type TransformTokenizationTestConfig struct {
	StoreConfig        *TransformStoreConfig        `hcl:"store,block"`
	StoreSchemaConfig  *TransformStoreSchemaConfig  `hcl:"store_schema,block"`
	RoleConfig         *TransformRoleConfig         `hcl:"role,block"`
	TokenizationConfig *TransformTokenizationConfig `hcl:"tokenization,block"`
	InputConfig        *TransformInputConfig        `hcl:"input,block"`
}

type TransformStoreConfig struct {
	Name                     string   `hcl:"name,optional"`
	Type                     string   `hcl:"type,optional"`
	Driver                   string   `hcl:"driver,optional"`
	ConnectionString         string   `hcl:"connection_string,optional"`
	Username                 string   `hcl:"username,optional"`
	Password                 string   `hcl:"password,optional"`
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
	t.config = &TransformTestConfig{
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
		},
	}

	diags := gohcl.DecodeBody(body, nil, t.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
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
	t.logger.Trace("unmounting", "path", hclog.Fmt("%v", t.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(t.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (t *TransformTokenizationTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := t.config.Config
	t.logger = targetLogger.Named(TransformTokenizationTestType)

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}
	t.logger = t.logger.Named(secretPath)

	// Create Transform mount
	t.logger.Trace("mounting transform secrets engine at", "path", hclog.Fmt("%v", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "transform",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling transform secrets engine: %v", err)
	}

	// Create Store config if provided
	if config.StoreConfig != nil {
		t.logger.Trace("configuring store")

		// Decode Store config struct to mapstructure to pass with request
		t.logger.Trace("decoding store config data")
		storeConfigData, err := structToMap(config.StoreConfig)
		if err != nil {
			return nil, fmt.Errorf("error decoding store config from struct: %v", err)
		}

		// Setup store
		t.logger.Trace("writing store config", "store", hclog.Fmt("%v", config.StoreConfig.Name))
		storePath := filepath.Join(secretPath, "stores", config.StoreConfig.Name)
		_, err = client.Logical().Write(storePath, storeConfigData)
		if err != nil {
			return nil, fmt.Errorf("error creating store %q: %v", config.StoreConfig.Name, err)
		}

		if config.StoreSchemaConfig != nil {
			t.logger.Trace("configuring store schema")

			// Decode Store config struct to mapstructure to pass with request
			t.logger.Trace("decoding store schema config data")
			storeSchemaConfigData, err := structToMap(config.StoreSchemaConfig)
			if err != nil {
				return nil, fmt.Errorf("error decoding store schema config from struct: %v", err)
			}

			// Setup store
			t.logger.Trace("writing schema for store", "store", hclog.Fmt("%v", config.StoreSchemaConfig.Name))
			storeSchemaPath := filepath.Join(secretPath, "stores", config.StoreSchemaConfig.Name, "schema")
			_, err = client.Logical().Write(storeSchemaPath, storeSchemaConfigData)
			if err != nil {
				return nil, fmt.Errorf("error creating store %q: %v", config.StoreSchemaConfig.Name, err)
			}
		}
	}

	// Decode Role data
	t.logger.Trace("decoding role config data")
	roleConfigData, err := structToMap(config.RoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding role config from struct: %v", err)
	}

	// Create Role
	t.logger.Trace("writing role", "name", hclog.Fmt("%v", config.RoleConfig.Name))
	rolePath := filepath.Join(secretPath, "role", config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error creating role %q: %v", config.RoleConfig.Name, err)
	}

	// Decode Tokenization Transformation data
	t.logger.Trace("decoding tokenization config data")
	tokenizationConfigData, err := structToMap(config.TokenizationConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding tokenization config from struct: %v", err)
	}

	// Create Transformation
	t.logger.Trace("writing tokenization transformation", "name", hclog.Fmt("%v", config.TokenizationConfig.Name))
	transformationPath := filepath.Join(secretPath, "transformations", "tokenization", config.TokenizationConfig.Name)
	_, err = client.Logical().Write(transformationPath, tokenizationConfigData)
	if err != nil {
		return nil, fmt.Errorf("error creating tokenization transformation %q: %v", config.TokenizationConfig.Name, err)
	}

	// Decode test data to be transformed
	t.logger.Trace("decoding test transformation data")
	testData, err := structToMap(config.InputConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding test input data from struct: %v", err)
	}

	testDataString, err := json.Marshal(testData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling test encode data: %v", err)
	}

	return &TransformTokenizationTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		body:       []byte(testDataString),
		roleName:   config.RoleConfig.Name,
		logger:     t.logger,
	}, nil
}

func (t *TransformTokenizationTest) Flags(fs *flag.FlagSet) {}
