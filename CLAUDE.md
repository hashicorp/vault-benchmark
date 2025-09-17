# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vault Benchmark is a Go-based CLI tool for performance testing HashiCorp Vault auth methods and secret engines using Vegeta HTTP load testing. It's designed to stress-test Vault clusters in isolated environments.

## Essential Development Commands

### Build & Development
- `make bin` - Build binary (output: `dist/{OS}/{ARCH}/vault-benchmark`)
- `make test` - Run all tests (`go test -race ./...`)
- `make fmt` - Format Go code (`gofmt`)
- `make mod` - Tidy Go modules
- `make clean` - Remove build artifacts

### Docker & Containerization
- `make image` - Build Docker image with versioning
- `docker compose up` - Start Vault + vault-benchmark containers
- `make cleanupimages` - Remove benchmark test images

### Usage
- `vault-benchmark run -config=config.hcl` - Execute benchmark tests
- `vault-benchmark review -config=config.hcl` - Review configuration

## Architecture & Code Structure

### Core Components
- **`main.go`** - Entry point, delegates to command package
- **`command/`** - CLI implementations (run, review commands)
- **`benchmarktests/`** - 57+ test implementations for various Vault engines
- **`config/`** - HCL configuration parsing and validation
- **`docs/`** - Test documentation and configuration examples

### Key Dependencies
- **Vault API** (`github.com/hashicorp/vault/api`) - Vault client operations
- **Vegeta** (`github.com/tsenart/vegeta/v12`) - HTTP load testing engine
- **HCL v2** (`github.com/hashicorp/hcl/v2`) - Configuration parsing
- **Prometheus** (`github.com/prometheus/client_golang`) - Metrics collection

### Test Implementation Pattern
Each benchmark test in `benchmarktests/` follows this structure:
1. **Registration** - `init()` function registers test type in `TestList`
2. **Config Struct** - HCL-tagged structs for configuration parsing
3. **Methods** - `ParseConfig()`, `Setup()`, `Target()`, `Cleanup()`, `GetTargetInfo()`
4. **Setup Process** - Mount engine → Configure resources → Prepare test data

### Configuration Format
Tests use HCL configuration with:
- Global settings (vault_addr, duration, cleanup, etc.)
- Test blocks defining weight distribution and specific config

## Development Environment

### Go Version
- **Required**: Go 1.23+ with toolchain 1.24.5
- **Build**: CGO_ENABLED=0 for static binaries

### Local Development
- Docker Compose setup available for Vault + benchmark container
- Test fixtures in `test-fixtures/` for validation
- Comprehensive documentation in `docs/tests/` for each test type

## Recent Development

### Transform FPE Test Implementation ✅ COMPLETED
**Objective**: Create credit card number FPE (Format Preserving Encryption) test with batch support

**Implementation Details**:
1. **New Files**:
   - `benchmarktests/target_secret_transform_fpe.go` - Main test implementation
   - `docs/tests/secret-transform-fpe.md` - Documentation

2. **Configuration**:
   ```go
   type TransformFPETestConfig struct {
       RoleConfig  *TransformRoleConfig     `hcl:"role,block"`
       FPEConfig   *TransformFPEConfig      `hcl:"fpe,block"`
       InputConfig *TransformFPEInputConfig `hcl:"input,block"`
   }

   type TransformFPEConfig struct {
       Name         string   `hcl:"name,optional"`         // "benchmarktransformation"
       Template     string   `hcl:"template,optional"`     // "builtin/creditcardnumber"
       TweakSource  string   `hcl:"tweak_source,optional"` // "internal"
       AllowedRoles []string `hcl:"allowed_roles,optional"`
   }

   type TransformFPEInputConfig struct {
       Value          string        `hcl:"value,optional"`       // Single CC: "4111-1111-1111-1111"
       DataMode       string        `hcl:"data_mode,optional"`   // "static" or "sequential"
       Transformation string        `hcl:"transformation,optional"`
       BatchSize      int          `hcl:"batch_size,optional"`   // NEW: 1,5,10,50,100+
       BatchInput     []interface{} `hcl:"batch_input,optional"`  // Custom batch data
   }
   ```

3. **Key Features**:
   - **Credit Card Focus**: Use `builtin/creditcardnumber` template exclusively
   - **Internal Tweaks**: `tweak_source: "internal"` for simplicity
   - **Batch Support**: Configurable batch sizes for performance testing
   - **API Target**: `POST /v1/{mount}/encode/{role}`

4. **Setup Process**:
   - Mount transform secrets engine
   - Create FPE transformation at `/transformations/fpe/{name}`
   - Create role linking to transformation
   - Generate batch test data based on batch_size and data_mode
   - Prepare JSON payload for encode operations

5. **Test Data Generation** ✅ IMPLEMENTED:
   - **Static Mode**: All requests use same CC number (default behavior)
   - **Sequential Mode**: Generate incremented CC numbers (4111-1111-1111-1111, 4111-1111-1111-1112, etc.)
   - Support both single value and batch operations
   - Handle configurable batch sizes for performance tuning