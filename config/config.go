package config

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/vault-tools/benchmark-vault/benchmarktests"
)

const (
	DefaultWorkers      = 10
	DefaultRPS          = 0
	DefaultDuration     = "10s"
	DefaultReportMode   = "terse"
	DefaultRandomMounts = true
	DefaultCleanup      = false
)

type VaultBenchmarkCoreConfig struct {
	Remain        hcl.Body                          `hcl:",remain"`
	VaultAddr     string                            `hcl:"vault_addr,optional"`
	VaultToken    string                            `hcl:"vault_token,optional"`
	Duration      string                            `hcl:"duration,optional"`
	ReportMode    string                            `hcl:"report_mode,optional"`
	AuditPath     string                            `hcl:"audit_path,optional"`
	Annotate      string                            `hcl:"annotate,optional"`
	ClusterJSON   string                            `hcl:"cluster_json,optional"`
	CAPEMFile     string                            `hcl:"ca_pem_file,optional"`
	PPROFInterval string                            `hcl:"pprof_interval,optional"`
	Tests         []*benchmarktests.BenchmarkTarget `hcl:"test,block"`
	RPS           int                               `hcl:"rps,optional"`
	Workers       int                               `hcl:"workers,optional"`
	RandomMounts  bool                              `hcl:"random_mounts,optional"`
	InputResults  bool                              `hcl:"input_results,optional"`
	Cleanup       bool                              `hcl:"cleanup,optional"`
	Debug         bool                              `hcl:"debug,optional"`
}

func NewVaultBenchmarkCoreConfig() *VaultBenchmarkCoreConfig {
	// Default Vault Benchmark Config Values
	return &VaultBenchmarkCoreConfig{
		Workers:      DefaultWorkers,
		RPS:          DefaultRPS,
		Duration:     DefaultDuration,
		ReportMode:   DefaultReportMode,
		RandomMounts: DefaultRandomMounts,
		Cleanup:      DefaultCleanup,
	}
}

// LoadConfig populates a VaultBenchmarkCoreConfig struct from the
// passed in HCL config file
func (c *VaultBenchmarkCoreConfig) LoadConfig(path string) error {
	var fileBuf []byte

	// File Validity checking
	if ok, err := benchmarktests.IsFile(path); ok {
		fileBuf, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
	} else {
		return fmt.Errorf("failed to open file: %v", err)
	}

	err := ParseConfig(fileBuf, path, c)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}
	return nil
}

func ParseConfig(hclBuf []byte, pathName string, configStruct *VaultBenchmarkCoreConfig) error {
	// HCL V2 Parsing
	parser := hclparse.NewParser()
	confFile, confDiags := parser.ParseHCL(hclBuf, pathName)
	if confDiags.HasErrors() {
		return fmt.Errorf("error parsing hcl: %v", confDiags)
	}

	// Decode HCL Body into Core Config Struct
	moreDiags := gohcl.DecodeBody(confFile.Body, nil, configStruct)
	if moreDiags.HasErrors() {
		return fmt.Errorf("error decoding hcl: %v", confDiags)
	}

	// Check to see if we have more than one Cert auth and fail if we do
	if moreThanOneTest(configStruct.Tests, benchmarktests.CertAuthTestType) {
		return fmt.Errorf("only one cert auth test supported")
	}

	// Loop through all found tests and check if they are part of the test list
	// then parse each test config based on provided test structs
	for _, vbTest := range configStruct.Tests {
		if currTest, ok := benchmarktests.TestList[vbTest.Type]; ok {
			currBuilder := currTest()
			err := currBuilder.ParseConfig(vbTest.Remain)
			if err != nil {
				return err
			}
			vbTest.Builder = currBuilder
		} else {
			return fmt.Errorf("invalid test type found: %v", vbTest.Type)
		}
	}
	return nil
}

// moreThanOneTest will fail out of config parsing we have more than one of the
// specified testType provided. This is to account for scenarios where due to other
// restrictions only one test type can be run for a given instance of vault-benchmark
func moreThanOneTest(tests []*benchmarktests.BenchmarkTarget, testType string) bool {
	targetMap := make(map[string]interface{})
	for _, target := range tests {
		if target.Type == testType {
			if _, ok := targetMap[target.Type]; !ok {
				targetMap[target.Type] = nil
				continue
			}
			return true
		}
	}
	return false
}
