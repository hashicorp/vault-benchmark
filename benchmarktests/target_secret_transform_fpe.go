// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

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
	TransformFPETestType   = "transform_fpe"
	TransformFPETestMethod = "POST"
)

func init() {
	TestList[TransformFPETestType] = func() BenchmarkBuilder {
		return &TransformFPETest{}
	}
}

type TransformFPETest struct {
	pathPrefix string
	header     http.Header
	body       []byte
	roleName   string
	config     *TransformFPETestConfig
	logger     hclog.Logger
}

type TransformFPETestConfig struct {
	RoleConfig     *TransformRoleConfig     `hcl:"role,block"`
	FPEConfig      *TransformFPEConfig      `hcl:"fpe,block"`
	AlphabetConfig *TransformAlphabetConfig `hcl:"alphabet,block"`
	InputConfig    *TransformFPEInputConfig `hcl:"input,block"`
}

// TransformFPEConfig maps to the /transform/transformations/fpe/:name endpoint.
type TransformFPEConfig struct {
	Name         string   `hcl:"name,optional"`
	Template     string   `hcl:"template,optional"`
	Templates    []string `hcl:"templates,optional"`
	TweakSource  string   `hcl:"tweak_source,optional"`
	AllowedRoles []string `hcl:"allowed_roles,optional"`
	MaxTweakLen  int      `hcl:"max_tweak_len,optional"`
}

// TransformAlphabetConfig maps to the /transform/alphabet/:name endpoint.
// When omitted the built-in "numeric" alphabet is used and this block is skipped.
type TransformAlphabetConfig struct {
	Name     string `hcl:"name,optional"`
	Alphabet string `hcl:"alphabet,optional"`
}

// TransformFPEInputConfig holds per-request encode parameters.
type TransformFPEInputConfig struct {
	Value          string        `hcl:"value,optional"`
	Transformation string        `hcl:"transformation,optional"`
	Tweak          string        `hcl:"tweak,optional"`
	Reference      string        `hcl:"reference,optional"`
	BatchInput     []interface{} `hcl:"batch_input,optional"`
}

func (t *TransformFPETest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *TransformFPETestConfig `hcl:"config,block"`
	}{
		Config: &TransformFPETestConfig{
			RoleConfig: &TransformRoleConfig{
				Name:            "benchmark-role",
				Transformations: []string{"benchmarktransformation"},
			},
			FPEConfig: &TransformFPEConfig{
				Name:         "benchmarktransformation",
				Template:     "builtin/creditcardnumber",
				TweakSource:  "internal",
				AllowedRoles: []string{"benchmark-role"},
				MaxTweakLen:  0,
			},
			InputConfig: &TransformFPEInputConfig{
				Transformation: "benchmarktransformation",
				Value:          "1111-1111-1111-1111",
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

func (t *TransformFPETest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: TransformFPETestMethod,
		URL:    client.Address() + t.pathPrefix + "/encode/" + t.roleName,
		Body:   t.body,
		Header: t.header,
	}
}

func (t *TransformFPETest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     TransformFPETestMethod,
		pathPrefix: t.pathPrefix,
	}
}

func (t *TransformFPETest) Cleanup(client *api.Client) error {
	t.logger.Trace(cleanupLogMessage(t.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(t.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (t *TransformFPETest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	t.logger = targetLogger.Named(TransformFPETestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Transform mount
	t.logger.Trace(mountLogMessage("secrets", "transform", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "transform",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting transform secrets engine: %v", err)
	}

	setupLogger := t.logger.Named(secretPath)

	// Optionally create a custom alphabet
	if t.config.AlphabetConfig != nil && t.config.AlphabetConfig.Name != "" {
		setupLogger.Trace(parsingConfigLogMessage("alphabet"))
		alphabetConfigData, err := structToMap(t.config.AlphabetConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing alphabet config from struct: %v", err)
		}

		setupLogger.Trace(writingLogMessage("alphabet"), "name", t.config.AlphabetConfig.Name)
		alphabetPath := filepath.Join(secretPath, "alphabet", t.config.AlphabetConfig.Name)
		_, err = client.Logical().Write(alphabetPath, alphabetConfigData)
		if err != nil {
			return nil, fmt.Errorf("error writing alphabet %q: %v", t.config.AlphabetConfig.Name, err)
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
	_, err = client.Logical().Write(rolePath, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing role %q: %v", t.config.RoleConfig.Name, err)
	}

	// Decode FPE Transformation data
	setupLogger.Trace(parsingConfigLogMessage("fpe transformation"))
	fpeConfigData, err := structToMap(t.config.FPEConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing fpe transformation config from struct: %v", err)
	}

	// Create FPE Transformation
	setupLogger.Trace(writingLogMessage("fpe transformation"), "name", t.config.FPEConfig.Name)
	transformationPath := filepath.Join(secretPath, "transformations", "fpe", t.config.FPEConfig.Name)
	_, err = client.Logical().Write(transformationPath, fpeConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing fpe transformation %q: %v", t.config.FPEConfig.Name, err)
	}

	// Decode test data to be encoded
	setupLogger.Trace("parsing test transformation input data")
	testData, err := structToMap(t.config.InputConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing test transformation input data from struct: %v", err)
	}

	testDataString, err := json.Marshal(testData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling test encode data: %v", err)
	}

	return &TransformFPETest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		body:       []byte(testDataString),
		roleName:   t.config.RoleConfig.Name,
		logger:     t.logger,
	}, nil
}

func (t *TransformFPETest) Flags(fs *flag.FlagSet) {}
