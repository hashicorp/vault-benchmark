package config

import (
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/vault-tools/benchmark-vault/benchmarktests"
)

type VaultBenchmarkCoreConfig struct {
	Remain        hcl.Body                          `hcl:",remain"`
	VaultAddr     string                            `hcl:"vault_addr" json:"vault_addr"`
	VaultToken    string                            `hcl:"vault_token" json:"vault_token"`
	Duration      string                            `hcl:"duration,optional" json:"duration"`
	ReportMode    string                            `hcl:"report_mode,optional" json:"report_mode"`
	AuditPath     string                            `hcl:"audit_path,optional" json:"audit_path"`
	Annotate      string                            `hcl:"annotate,optional" json:"annotate"`
	ClusterJSON   string                            `hcl:"cluster_json,optional" json:"cluster_json"`
	CAPEMFile     string                            `hcl:"ca_pem_file,optional" json:"ca_pem_file"`
	PPROFInterval string                            `hcl:"pprof_interval,optional" json:"pprof_interval"`
	Tests         []*benchmarktests.BenchmarkTarget `hcl:"test,block"`
	RPS           int                               `hcl:"rps,optional" json:"rps"`
	Workers       int                               `hcl:"workers,optional" json:"workers"`
	RandomMounts  bool                              `hcl:"random_mounts,optional"`
	InputResults  bool                              `hcl:"input_results,optional" json:"input_results"`
	Cleanup       bool                              `hcl:"cleanup,optional" json:"cleanup"`
}

func NewVaultBenchmarkCoreConfig() *VaultBenchmarkCoreConfig {
	// Default Vault Benchmark Config Values
	return &VaultBenchmarkCoreConfig{
		Workers:      10,
		RPS:          0,
		Duration:     "10s",
		ReportMode:   "terse",
		RandomMounts: true,
		Cleanup:      false,
	}
}

// TODO:
// Move warnings and errors to proper logger
func (c *VaultBenchmarkCoreConfig) LoadConfig(path string) error {
	// File Validity checking
	f, err := os.Stat(path)
	if err != nil {
		return err
	}

	if f.IsDir() {
		return fmt.Errorf("location is a directory, not a file")
	}

	// HCL V2 Parsing
	parser := hclparse.NewParser()
	confFile, confDiags := parser.ParseHCLFile(path)
	if confDiags.HasErrors() {
		fmt.Println(confDiags)
	}

	// Decode HCL Body into Core Config Struct
	moreDiags := gohcl.DecodeBody(confFile.Body, nil, c)
	if moreDiags.HasErrors() {
		fmt.Println(moreDiags)
	}

	// Check to see if we have more than one Cert auth and fail if we do
	if moreThanOneCertAuth(c.Tests) {
		return fmt.Errorf("only one cert auth test supported")
	}

	// Loop through all found tests and check if they are part of the test list
	// then parse each test config based on provided test structs
	for _, vbTest := range c.Tests {
		if currTest, ok := benchmarktests.TestList[vbTest.Type]; ok {
			currBuilder := currTest()
			currBuilder.ParseConfig(vbTest.Remain)
			vbTest.Builder = currBuilder
		} else {
			log.Fatalf("invalid test type found: %v", vbTest.Type)
		}
	}
	return nil
}

func moreThanOneCertAuth(tests []*benchmarktests.BenchmarkTarget) bool {
	targetMap := make(map[string]interface{})
	for _, target := range tests {
		if _, ok := targetMap[benchmarktests.CertAuthTestType]; !ok {
			targetMap[target.Type] = nil
			continue
		}
		return true
	}
	return false
}
