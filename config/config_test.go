// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

const (
	BadCoreConfig = `
	report_mode = terse	
`
	FixturePath = "../test-fixtures/configs"
)

func TestLoadConfig(t *testing.T) {
	conf := NewVaultBenchmarkCoreConfig()
	err := conf.LoadConfig(filepath.Join(FixturePath, "config.hcl"))
	if err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestLoadConfig_Path(t *testing.T) {
	conf := NewVaultBenchmarkCoreConfig()
	err := conf.LoadConfig(FixturePath)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadConfig_NoExist(t *testing.T) {
	conf := NewVaultBenchmarkCoreConfig()
	err := conf.LoadConfig(filepath.Join(FixturePath, "nope/negative/.no"))
	if err == nil {
		t.Fatalf("expected error: %s", err)
	}
}

func TestParseConfig_InvalidTest(t *testing.T) {
	conf := NewVaultBenchmarkCoreConfig()
	err := ParseConfig([]byte(`test "invalid" "nope" {this="invalid"}`), "test", conf)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `invalid test type found: invalid`) {
		t.Errorf("bad error: %s", err.Error())
	}
}

func TestParseConfig_InvalidValueType(t *testing.T) {
	conf := NewVaultBenchmarkCoreConfig()
	err := ParseConfig([]byte(BadCoreConfig), "test", conf)
	if err == nil {
		t.Fatal("expected error")
	}
}
