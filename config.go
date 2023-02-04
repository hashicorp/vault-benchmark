package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/vault-tools/benchmark-vault/benchmark_tests"
)

type BenchmarkVaultCoreConfig struct {
	VaultAddr     string                           `hcl:"vault_addr" json:"vault_addr"`
	VaultToken    string                           `hcl:"vault_token" json:"vault_token"`
	Workers       int                              `hcl:"workers,optional" json:"workers"`
	Duration      string                           `hcl:"duration,optional" json:"duration"`
	RPS           int                              `hcl:"rps,optional" json:"rps"`
	ReportMode    string                           `hcl:"report_mode,optional" json:"report_mode"`
	Annotate      string                           `hcl:"annotate,optional" json:"annotate"`
	InputResults  bool                             `hcl:"input_results,optional" json:"input_results"`
	ClusterJSON   string                           `hcl:"cluster_json,optional" json:"cluster_json"`
	CAPEMFile     string                           `hcl:"ca_pem_file,optional" json:"ca_pem_file"`
	PPROFInterval string                           `hcl:"pprof_interval,optional" json:"pprof_interval"`
	AuditPath     string                           `hcl:"audit_path,optional" json:"audit_path"`
	Debug         bool                             `hcl:"debug,optional" json:"debug"`
	RandomMounts  bool                             `hcl:"random_mounts,optional"`
	Test          []*benchmark_tests.BenchmarkTest `hcl:"test,block"`
	Remain        hcl.Body                         `hcl:",remain"`
}

func NewConfig() *BenchmarkVaultCoreConfig {
	return &BenchmarkVaultCoreConfig{}
}

func LoadConfig(path string) (*BenchmarkVaultCoreConfig, error) {
	// File Validity checking
	f, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if f.IsDir() {
		return nil, fmt.Errorf("location is a directory, not a file")
	}

	// HCL V2 Parsing
	var diags hcl.Diagnostics
	parser := hclparse.NewParser()
	confFile, confDiags := parser.ParseHCLFile(path)

	diags = append(diags, confDiags...)
	if diags.HasErrors() {
		fmt.Println("File Parse Diags")
		fmt.Println(diags)
	}

	// Decode HCL Body into Config Struct
	c := NewConfig()
	moreDiags := gohcl.DecodeBody(confFile.Body, nil, c)
	diags = append(diags, moreDiags...)
	if diags.HasErrors() {
		fmt.Println("First pass decode diags")
		fmt.Println(diags)
	}

	// Loop through all found tests and check if they are part of the test list
	// and parse test config based on provided test structs
	for i, bvTest := range c.Test {
		for testType, testObject := range benchmark_tests.TestList {
			if bvTest.Type == testType {
				// Found test in list, parse config
				c.Test[i].Config = testObject().ParseConfig(bvTest.Remain)
				c.Test[i].Builder = testObject()
			}
		}
	}
	return c, nil
}
