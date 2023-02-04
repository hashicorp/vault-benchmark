package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// Generic Benchmark Test config structure
type BenchmarkTest struct {
	Name   string `hcl:"name,label"`
	Type   string `hcl:"type,label"`
	Weight int    `hcl:"weight,optional"`
	Config interface{}
	Remain hcl.Body `hcl:",remain"`
}

type BenchmarkVaultCoreConfig struct {
	VaultAddr     string          `hcl:"vault_addr" json:"vault_addr"`
	VaultToken    string          `hcl:"vault_token" json:"vault_token"`
	Workers       int             `hcl:"workers,optional" json:"workers"`
	Duration      string          `hcl:"duration,optional" json:"duration"`
	RPS           int             `hcl:"rps,optional" json:"rps"`
	ReportMode    string          `hcl:"report_mode,optional" json:"report_mode"`
	Annotate      string          `hcl:"annotate,optional" json:"annotate"`
	InputResults  bool            `hcl:"input_results,optional" json:"input_results"`
	ClusterJSON   string          `hcl:"cluster_json,optional" json:"cluster_json"`
	CAPEMFile     string          `hcl:"ca_pem_file,optional" json:"ca_pem_file"`
	PPROFInterval string          `hcl:"pprof_interval,optional" json:"pprof_interval"`
	AuditPath     string          `hcl:"audit_path,optional" json:"audit_path"`
	Debug         bool            `hcl:"debug,optional" json:"debug"`
	RandomMounts  bool            `hcl:"random_mounts,optional"`
	Test          []BenchmarkTest `hcl:"test,block"`
	Remain        hcl.Body        `hcl:",remain"`
}

func NewConfig() *BenchmarkVaultCoreConfig {
	return &BenchmarkVaultCoreConfig{}
}

func LoadConfig(path string) (*BenchmarkVaultCoreConfig, error) {
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
		fmt.Println(diags)
	}

	c := NewConfig()

	moreDiags := gohcl.DecodeBody(confFile.Body, nil, c)
	diags = append(diags, moreDiags...)
	if diags.HasErrors() {
		fmt.Println(diags)
	}

	for i, test := range c.Test {
		if test.Type == "approle_auth" {
			tempConfig := &ApproleAuthTestConfig{}
			moreDiags := gohcl.DecodeBody(test.Remain, nil, tempConfig)
			diags = append(diags, moreDiags...)
			if diags.HasErrors() {
				fmt.Println("Inner", diags)
			}
			c.Test[i].Config = tempConfig
		}
	}

	return c, nil
}
