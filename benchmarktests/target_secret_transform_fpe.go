// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
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
	RoleConfig  *TransformRoleConfig     `hcl:"role,block"`
	FPEConfig   *TransformFPEConfig      `hcl:"fpe,block"`
	InputConfig *TransformFPEInputConfig `hcl:"input,block"`
}

type TransformFPEInputConfig struct {
	Value          string        `hcl:"value,optional"`
	DataMode       string        `hcl:"data_mode,optional"`
	Transformation string        `hcl:"transformation,optional"`
	BatchSize      int           `hcl:"batch_size,optional"`
	BatchInput     []interface{} `hcl:"batch_input,optional"`
}

type TransformFPEConfig struct {
	Name         string   `hcl:"name,optional"`
	Template     string   `hcl:"template,optional"`
	TweakSource  string   `hcl:"tweak_source,optional"`
	AllowedRoles []string `hcl:"allowed_roles,optional"`
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
			},
			InputConfig: &TransformFPEInputConfig{
				Transformation: "benchmarktransformation",
				Value:          "4111-1111-1111-1111",
				DataMode:       "static",
				BatchSize:      0,
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
	setupLogger.Trace("decoding FPE config data")
	fpeConfigData, err := structToMap(t.config.FPEConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding FPE config from struct: %v", err)
	}

	// Create Transformation
	setupLogger.Trace(writingLogMessage("FPE transformation"), "name", t.config.FPEConfig.Name)
	transformationPath := filepath.Join(secretPath, "transformations", "fpe", t.config.FPEConfig.Name)
	_, err = client.Logical().Write(transformationPath, fpeConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing FPE transformation %q: %v", t.config.FPEConfig.Name, err)
	}

	// Prepare test data
	setupLogger.Trace("parsing test transformation input data")
	var testData interface{}

	if t.config.InputConfig.BatchSize > 0 {
		// Generate batch input
		batchInput := make([]map[string]interface{}, t.config.InputConfig.BatchSize)
		for i := 0; i < t.config.InputConfig.BatchSize; i++ {
			var ccValue string
			if t.config.InputConfig.DataMode == "sequential" {
				ccValue = generateSequentialCCNumber(t.config.InputConfig.Value, i)
			} else {
				ccValue = t.config.InputConfig.Value
			}
			batchInput[i] = map[string]interface{}{
				"value":          ccValue,
				"transformation": t.config.InputConfig.Transformation,
			}
		}
		testData = map[string]interface{}{
			"batch_input": batchInput,
		}
	} else if len(t.config.InputConfig.BatchInput) > 0 {
		// Use provided batch input
		testData = map[string]interface{}{
			"batch_input": t.config.InputConfig.BatchInput,
		}
	} else {
		// Single value input
		inputConfigData, err := structToMap(t.config.InputConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing test transformation input data from struct: %v", err)
		}
		testData = inputConfigData
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

// generateSequentialCCNumber generates a credit card number by incrementing the last 4 digits
func generateSequentialCCNumber(baseCC string, increment int) string {
	// Find the last dash to identify the last 4 digits
	lastDashIndex := strings.LastIndex(baseCC, "-")
	if lastDashIndex == -1 {
		// No dashes found, assume the last 4 characters are the ones to increment
		if len(baseCC) < 4 {
			return baseCC
		}
		prefix := baseCC[:len(baseCC)-4]
		lastFourStr := baseCC[len(baseCC)-4:]
		lastFour, err := strconv.Atoi(lastFourStr)
		if err != nil {
			return baseCC // Return original if parsing fails
		}
		newLastFour := lastFour + increment
		return fmt.Sprintf("%s%04d", prefix, newLastFour)
	}

	// Extract parts
	prefix := baseCC[:lastDashIndex+1]
	lastFourStr := baseCC[lastDashIndex+1:]

	// Convert last 4 digits to integer and increment
	lastFour, err := strconv.Atoi(lastFourStr)
	if err != nil {
		return baseCC // Return original if parsing fails
	}

	newLastFour := lastFour + increment
	return fmt.Sprintf("%s%04d", prefix, newLastFour)
}