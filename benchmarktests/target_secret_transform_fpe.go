// Copyright IBM Corp. 2022, 2025
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
	RoleConfig  *TransformRoleConfig  `hcl:"role,block"`
	FPEConfig   *TransformFPEConfig   `hcl:"fpe,block"`
	InputConfig *TransformInputConfig `hcl:"input,block"`
}
type TransformFPEConfig struct {
	Name         string   `hcl:"name,optional"`
	Template     string   `hcl:"template,optional"`
	TweakSource  string   `hcl:"tweak_source,optional"`
	AllowedRoles []string `hcl:"allowed_roles,optional"`
}
type TransformFPETemplateConfig struct {
	Name     string `hcl:"name,optional"`
	Type     string `hcl:"type,optional"`
	Pattern  string `hcl:"pattern,optional"`
	Alphabet string `hcl:"alphabet,optional"`
}

func (t *TransformFPETest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *TransformFPETestConfig `hcl:"config,block"`
	}{
		Config: &TransformFPETestConfig{
			RoleConfig: &TransformRoleConfig{
				Name:            "benchmark-role",
				Transformations: []string{"benchmarkfpetransformation"},
			},
			FPEConfig: &TransformFPEConfig{
				Name:         "benchmarkfpetransformation",
				Template:     "benchmarkfpetemplate",
				TweakSource:  "internal",
				AllowedRoles: []string{"benchmark-role"},
			},
			InputConfig: &TransformInputConfig{
				Transformation: "benchmarkfpetransformation",
				Value:          "1111-2222-3333-4444",
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
	// Create FPE Template
	setupLogger.Trace(writingLogMessage("fpe template"), "name", t.config.FPEConfig.Template)
	templatePath := filepath.Join(secretPath, "template", t.config.FPEConfig.Template)
	_, err = client.Logical().Write(templatePath, map[string]interface{}{
		"type":     "regex",
		"pattern":  `(\d{4})-(\d{4})-(\d{4})-(\d{4})`,
		"alphabet": "builtin/numeric",
	})
	if err != nil {
		return nil, fmt.Errorf("error writing FPE template %q: %v", t.config.FPEConfig.Template, err)
	}
	// Decode FPE Transformation config
	setupLogger.Trace(parsingConfigLogMessage("fpe"))
	fpeConfigData, err := structToMap(t.config.FPEConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing FPE config from struct: %v", err)
	}
	// Create FPE Transformation
	setupLogger.Trace(writingLogMessage("fpe transformation"), "name", t.config.FPEConfig.Name)
	transformationPath := filepath.Join(secretPath, "transformations", "fpe", t.config.FPEConfig.Name)
	_, err = client.Logical().Write(transformationPath, fpeConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing FPE transformation %q: %v", t.config.FPEConfig.Name, err)
	}
	// Decode Role config
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
	// Decode test input data
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
