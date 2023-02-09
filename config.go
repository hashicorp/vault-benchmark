package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/vault-tools/benchmark-vault/benchmark_tests"
)

type VaultBenchmarkCoreConfig struct {
	Remain        hcl.Body                           `hcl:",remain"`
	VaultAddr     string                             `hcl:"vault_addr" json:"vault_addr"`
	VaultToken    string                             `hcl:"vault_token" json:"vault_token"`
	Duration      string                             `hcl:"duration,optional" json:"duration"`
	ReportMode    string                             `hcl:"report_mode,optional" json:"report_mode"`
	AuditPath     string                             `hcl:"audit_path,optional" json:"audit_path"`
	Annotate      string                             `hcl:"annotate,optional" json:"annotate"`
	ClusterJSON   string                             `hcl:"cluster_json,optional" json:"cluster_json"`
	CAPEMFile     string                             `hcl:"ca_pem_file,optional" json:"ca_pem_file"`
	PPROFInterval string                             `hcl:"pprof_interval,optional" json:"pprof_interval"`
	Tests         []*benchmark_tests.BenchmarkTarget `hcl:"test,block"`
	RPS           int                                `hcl:"rps,optional" json:"rps"`
	Workers       int                                `hcl:"workers,optional" json:"workers"`
	Debug         bool                               `hcl:"debug,optional" json:"debug"`
	RandomMounts  bool                               `hcl:"random_mounts,optional"`
	InputResults  bool                               `hcl:"input_results,optional" json:"input_results"`
}

func NewVaultBenchmarkCoreConfig() *VaultBenchmarkCoreConfig {
	return &VaultBenchmarkCoreConfig{}
}

func LoadConfig(path string) (*VaultBenchmarkCoreConfig, error) {
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

	// Decode HCL Body into Core Config Struct
	c := NewVaultBenchmarkCoreConfig()
	moreDiags := gohcl.DecodeBody(confFile.Body, nil, c)
	diags = append(diags, moreDiags...)
	if diags.HasErrors() {
		fmt.Println("First pass decode diags")
		fmt.Println(diags)
	}

	// Loop through all found tests and check if they are part of the test list
	// then parse each test config based on provided test structs
	for i, bvTest := range c.Tests {
		for testType, testObject := range benchmark_tests.TestList {
			if bvTest.Type == testType {
				// Found test in list, parse config
				currTest := testObject()
				currTest.ParseConfig(bvTest.Remain)
				c.Tests[i].Builder = currTest
			}
			//TODO: What do we do if we don't find the test?
		}
	}
	return c, nil
}
