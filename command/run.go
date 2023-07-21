// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-benchmark/benchmarktests"
	vbConfig "github.com/hashicorp/vault-benchmark/config"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// maxLineLength is the maximum width of any line.
	maxLineLength int = 78
)

var (
	_ cli.Command             = (*RunCommand)(nil)
	_ cli.CommandAutocomplete = (*RunCommand)(nil)
)

type RunCommand struct {
	*BaseCommand
	flagVaultAddr        string
	flagVaultToken       string
	flagAuditPath        string
	flagVBCoreConfigPath string
	flagCAPEMFile        string
	flagVaultNamespace   string
	flagWorkers          int
	flagRPS              int
	flagDuration         time.Duration
	flagReportMode       string
	flagPPROFInterval    time.Duration
	flagAnnotate         string
	flagRandomMounts     bool
	flagCleanup          bool
	flagDebug            bool
	flagClusterJson      string
	flagLogLevel         string
}

func (r *RunCommand) Synopsis() string {
	return "Run vault-benchmark test(s)"
}

func (r *RunCommand) Help() string {
	helpText := `
Usage: vault-benchmark run [options]

 This command will run a vault-benchmark test.

 Run a vault-benchmark test with a configuration file:

	$ vault-benchmark run -config=/etc/vault-benchmark/test.hcl

 For a full list of examples, please see the documentation.

` + r.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (r *RunCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (r *RunCommand) AutocompleteFlags() complete.Flags {
	return r.Flags().Completions()
}

func (r *RunCommand) Flags() *FlagSets {
	set := r.flagSet()
	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:    "vault_addr",
		EnvVar:  "VAULT_ADDR",
		Target:  &r.flagVaultAddr,
		Default: "http://127.0.0.1:8200",
		Usage:   "Target Vault API Address.",
	})

	f.StringVar(&StringVar{
		Name:    "vault_token",
		EnvVar:  "VAULT_TOKEN",
		Target:  &r.flagVaultToken,
		Default: "",
		Usage:   "Vault Token to be used for test setup.",
	})

	f.StringVar(&StringVar{
		Name:    "vault_namespace",
		EnvVar:  "VAULT_NAMESPACE",
		Target:  &r.flagVaultNamespace,
		Usage:   "Vault Namespace to create test mounts.",
		Default: "",
	})

	f.StringVar(&StringVar{
		Name:   "config",
		Target: &r.flagVBCoreConfigPath,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
		),
		Usage: "Path to a vault-benchmark test configuration file.",
	})

	f.IntVar(&IntVar{
		Name:    "workers",
		Target:  &r.flagWorkers,
		Default: 10,
		Usage:   "Number of workers",
	})

	f.IntVar(&IntVar{
		Name:    "rps",
		Target:  &r.flagRPS,
		Default: 0,
		Usage:   "Requests per second. Setting to 0 means as fast as possible.",
	})

	f.DurationVar(&DurationVar{
		Name:    "duration",
		Target:  &r.flagDuration,
		Default: 10 * time.Second,
		Usage:   "Test Duration.",
	})

	f.StringVar(&StringVar{
		Name:    "report_mode",
		Target:  &r.flagReportMode,
		Default: "terse",
		Usage:   "Reporting Mode. Options are: terse, verbose, json.",
	})

	f.DurationVar(&DurationVar{
		Name:    "pprof_interval",
		Target:  &r.flagPPROFInterval,
		Default: 0,
		Usage:   "Collection interval for vault debug pprof profiling.",
	})

	f.StringVar(&StringVar{
		Name:    "annotate",
		Target:  &r.flagAnnotate,
		Default: "",
		Usage:   "Comma-separated name=value pairs include in bench_running prometheus metric. Try name 'testname' for dashboard example.",
	})

	f.StringVar(&StringVar{
		Name:    "audit_path",
		Target:  &r.flagAuditPath,
		Default: "",
		Usage:   "Path to file for audit log.",
	})

	f.StringVar(&StringVar{
		Name:    "ca_pem_file",
		Target:  &r.flagCAPEMFile,
		EnvVar:  "VAULT_CACERT",
		Default: "",
		Usage:   "Path to PEM encoded CA file to verify external Vault.",
	})

	f.StringVar(&StringVar{
		Name:    "cluster_json",
		Target:  &r.flagClusterJson,
		Default: "",
		Usage:   "Path to cluster.json file",
	})

	f.BoolVar(&BoolVar{
		Name:    "random_mounts",
		Target:  &r.flagRandomMounts,
		Default: true,
		Usage:   "Use random mount names.",
	})

	f.BoolVar(&BoolVar{
		Name:    "cleanup",
		Target:  &r.flagCleanup,
		Default: false,
		Usage:   "Cleanup benchmark artifacts after run.",
	})

	f.StringVar(&StringVar{
		Name:    "log_level",
		Target:  &r.flagLogLevel,
		Default: "INFO",
		EnvVar:  "VAULT_BENCHMARK_LOG_LEVEL",
		Usage:   "Level to emit logs. Options are: INFO, WARN, DEBUG, TRACE.",
	})

	f.BoolVar(&BoolVar{
		Name:    "debug",
		Target:  &r.flagDebug,
		Default: false,
		Usage:   "Run vault-benchmark in Debug mode.",
	})

	// Add any additional flags from tests
	for _, vbTest := range benchmarktests.TestList {
		vbTest().Flags(f.mainSet)
		vbTest().Flags(f.flagSet)
	}

	return set
}

func (r *RunCommand) Run(args []string) int {
	benchmarkLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "vault-benchmark",
		Level: hclog.Info,
	})

	// Parse Flags
	f := r.Flags()
	if err := f.Parse(args); err != nil {
		benchmarkLogger.Error("error parsing flags", "error", hclog.Fmt("%v", err))
		return 1
	}

	// Load config from File
	if r.flagVBCoreConfigPath == "" {
		benchmarkLogger.Error("no config file location passed")
		return 1
	}

	conf := vbConfig.NewVaultBenchmarkCoreConfig()
	err := conf.LoadConfig(r.flagVBCoreConfigPath)
	if err != nil {
		benchmarkLogger.Error("error loading config", "error", hclog.Fmt("%v", err))
		return 1
	}

	r.applyConfigOverrides(f, conf)
	benchmarkLogger.SetLevel(hclog.LevelFromString(conf.LogLevel))

	// Parse Duration from configuration string
	parsedDuration, err := time.ParseDuration(conf.Duration)
	if err != nil {
		benchmarkLogger.Error("error parsing test duration from configuration", "error", hclog.Fmt("%v", err))
	}

	// Parse pprof Interval from configuration string
	var parsedPPROFinterval time.Duration
	if conf.PPROFInterval != "" {
		parsedPPROFinterval, err = time.ParseDuration(conf.PPROFInterval)
		if err != nil {
			benchmarkLogger.Error("error parsing pprof interval from configuration", "error", hclog.Fmt("%v", err))
			return 1
		}
	}

	if (!conf.RandomMounts) && (conf.Cleanup) {
		benchmarkLogger.Error("cleanup can only be enabled when random mounts is enabled")
		return 1
	}

	switch conf.ReportMode {
	case "terse", "verbose", "json":
	default:
		benchmarkLogger.Error("report_mode must be one of terse, verbose, or json")
	}

	var cluster struct {
		Token      string   `json:"token"`
		VaultAddrs []string `json:"vault_addrs"`
	}

	switch {
	case conf.ClusterJSON != "":
		b, err := os.ReadFile(conf.ClusterJSON)
		if err != nil {
			benchmarkLogger.Error(fmt.Sprintf("error reading cluster_json file: %q", conf.ClusterJSON), "error", hclog.Fmt("%v", err))
			return 1
		}
		err = json.Unmarshal(b, &cluster)
		if err != nil {
			benchmarkLogger.Error(fmt.Sprintf("error decoding cluster_json file: %q", conf.ClusterJSON), "error", hclog.Fmt("%v", err))
			return 1
		}
	case conf.VaultAddr != "":
		cluster.VaultAddrs = []string{conf.VaultAddr}
	default:
		benchmarkLogger.Error("must specify one of cluster_json, vault_addr, or $VAULT_ADDR")
	}

	if conf.VaultToken != "" {
		cluster.Token = conf.VaultToken
	}
	if conf.VaultToken == "" && cluster.Token == "" {
		benchmarkLogger.Error("must specify one of the following: cluster_json, vault_token, or $VAULT_TOKEN")
		return 1
	}

	// Setup annotations and testRunning metric
	var annoLabels []string
	var annoValues []string
	if conf.Annotate != "" {
		for _, kv := range strings.Split(conf.Annotate, ",") {
			kvPair := strings.SplitN(kv, "=", 2)
			if len(kvPair) != 2 || kvPair[0] == "" {
				benchmarkLogger.Error("annotate should contain comma-separated list of name=value pairs", "got", conf.Annotate)
				return 1
			}
			annoLabels = append(annoLabels, kvPair[0])
			annoValues = append(annoValues, kvPair[1])
		}
	}

	testRunning := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bench_running",
		Help: "is the benchmark attack executing",
	}, annoLabels)
	prometheus.MustRegister(testRunning)
	testRunning.WithLabelValues(annoValues...).Set(0)

	// Setup our prometheus listener
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		_ = http.ListenAndServe(":2112", nil)
	}()

	// Create vault clients
	var clients []*vaultapi.Client
	for _, addr := range cluster.VaultAddrs {
		tlsCfg := &vaultapi.TLSConfig{}
		cfg := vaultapi.DefaultConfig()
		if conf.CAPEMFile != "" {
			tlsCfg.CACert = conf.CAPEMFile
		}
		err := cfg.ConfigureTLS(tlsCfg)
		if err != nil {
			benchmarkLogger.Error("error creating vault client", "error", hclog.Fmt("%v", err))
			return 1
		}
		cfg.Address = addr
		client, err := vaultapi.NewClient(cfg)
		if err != nil {
			benchmarkLogger.Error("error creating vault client", "error", hclog.Fmt("%v", err))
			return 1
		}
		client.SetToken(cluster.Token)
		client.SetNamespace(conf.VaultNamespace)
		clients = append(clients, client)
	}

	var wg sync.WaitGroup

	if parsedPPROFinterval.Seconds() != 0 {
		_ = os.Setenv("VAULT_ADDR", cluster.VaultAddrs[0])
		_ = os.Setenv("VAULT_TOKEN", cluster.Token)
		if conf.CAPEMFile != "" {
			_ = os.Setenv("VAULT_CACERT", conf.CAPEMFile)
		}
		cmd := exec.Command("vault", "debug", "-duration", (2 * parsedDuration).String(),
			"-interval", parsedPPROFinterval.String(), "-compress=false")
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := cmd.CombinedOutput()
			if err != nil {
				benchmarkLogger.Error("error running pprof", "error", hclog.Fmt("%v", err))
			}
			benchmarkLogger.Info(fmt.Sprintf("pprof: %s", out))
		}()

		defer func() {
			// We can't use CommandContext because that uses sigkill, and we
			// want the debug process to wrap things up and write indexes/etc.
			benchmarkLogger.Info("stopping pprof")
			cmd.Process.Signal(os.Interrupt)
		}()
	}

	// Enable file audit device at specified path if flag set
	if conf.AuditPath != "" {
		err := clients[0].Sys().EnableAuditWithOptions("bench-audit", &vaultapi.EnableAuditOptions{
			Type: "file",
			Options: map[string]string{
				"file_path": conf.AuditPath,
			},
		})
		if err != nil {
			benchmarkLogger.Error("error enabling audit device", "error", hclog.Fmt("%v", err))
			return 1
		}
	}

	testRunning.WithLabelValues(annoValues...).Set(1)
	benchmarkLogger.Info("setting up targets")

	topLevelConfig := benchmarktests.TopLevelTargetConfig{
		Duration:     parsedDuration,
		RandomMounts: conf.RandomMounts,
	}

	tm, err := benchmarktests.BuildTargets(clients[0], conf.Tests, &benchmarkLogger, &topLevelConfig)
	if err != nil {
		benchmarkLogger.Error(fmt.Sprintf("target setup failed: %v", err))
		return 1
	}

	var l sync.Mutex
	results := make(map[string]*benchmarktests.Reporter)
	benchmarkLogger.Info("starting benchmarks", "duration", hclog.Fmt("%v", parsedDuration.String()))
	for _, client := range clients {
		wg.Add(1)
		go func(client *vaultapi.Client) {
			defer wg.Done()

			if r.flagDebug {
				if !benchmarkLogger.IsTrace() {
					benchmarkLogger.SetLevel(hclog.Debug)
				}
				l.Lock()
				benchmarkLogger.Debug("=== Debug Info ===")
				benchmarkLogger.Debug(fmt.Sprintf("Client: %s", client.Address()))
				tm.DebugInfo(client)
				l.Unlock()
			}

			rpt, err := benchmarktests.Attack(tm, client, parsedDuration, conf.RPS, conf.Workers)
			if err != nil {
				benchmarkLogger.Error("attack error", "err", hclog.Fmt("%v", err))
				os.Exit(1)
			}

			l.Lock()
			// TODO rethink how we present results when multiple nodes are attacked
			results[client.Address()] = rpt
			l.Unlock()

			if conf.Cleanup {
				benchmarkLogger.Info("cleaning up targets")
				err := tm.Cleanup(client)
				if err != nil {
					benchmarkLogger.Error("cleanup error", "err", hclog.Fmt("%v", err))
				}
				if conf.AuditPath != "" {
					_, err := client.Logical().Delete("/sys/audit/bench-audit")
					if err != nil {
						benchmarkLogger.Error("error disabling bench-audit audit device", "error", hclog.Fmt("%v", err))
					}
				}
			}
		}(client)
	}

	wg.Wait()

	testRunning.WithLabelValues(annoValues...).Set(0)
	benchmarkLogger.Info("benchmark complete")
	for _, client := range clients {
		addr := client.Address()
		rpt := results[addr]
		switch conf.ReportMode {
		case "json":
			rpt.ReportJSON(os.Stdout)
		case "verbose":
			rpt.ReportVerbose(os.Stdout)
		default:
			rpt.ReportTerse(os.Stdout)
		}
		fmt.Println()
	}
	return 0
}

func (r *RunCommand) applyConfigOverrides(f *FlagSets, config *vbConfig.VaultBenchmarkCoreConfig) {
	r.setDurationFlag(f, config.PPROFInterval, &DurationVar{
		Name:    "pprof_interval",
		Target:  &r.flagPPROFInterval,
		Default: 0,
	})
	config.PPROFInterval = r.flagPPROFInterval.String()

	r.setDurationFlag(f, config.Duration, &DurationVar{
		Name:    "duration",
		Target:  &r.flagDuration,
		Default: 10 * time.Second,
	})
	config.Duration = r.flagDuration.String()

	r.setIntFlag(f, config.RPS, &IntVar{
		Name:    "rps",
		Target:  &r.flagRPS,
		Default: 0,
	})
	config.RPS = r.flagRPS

	r.setIntFlag(f, config.Workers, &IntVar{
		Name:    "workers",
		Target:  &r.flagWorkers,
		Default: 10,
	})
	config.Workers = r.flagWorkers

	r.setStringFlag(f, config.VaultToken, &StringVar{
		Name:    "vault_token",
		EnvVar:  "VAULT_TOKEN",
		Target:  &r.flagVaultToken,
		Default: "",
	})
	config.VaultToken = r.flagVaultToken

	r.setStringFlag(f, config.VaultAddr, &StringVar{
		Name:    "vault_addr",
		EnvVar:  "VAULT_ADDR",
		Target:  &r.flagVaultAddr,
		Default: "http://127.0.0.1:8200",
	})
	config.VaultAddr = r.flagVaultAddr

	r.setStringFlag(f, config.VaultNamespace, &StringVar{
		Name:    "vault_namespace",
		EnvVar:  "VAULT_NAMESPACE",
		Target:  &r.flagVaultNamespace,
		Default: "",
	})
	config.VaultNamespace = r.flagVaultNamespace

	r.setStringFlag(f, config.ReportMode, &StringVar{
		Name:    "report_mode",
		Target:  &r.flagReportMode,
		Default: "terse",
	})
	config.ReportMode = r.flagReportMode

	r.setStringFlag(f, config.Annotate, &StringVar{
		Name:    "annotate",
		Target:  &r.flagAnnotate,
		Default: "",
	})
	config.AuditPath = r.flagAnnotate

	r.setStringFlag(f, config.AuditPath, &StringVar{
		Name:    "audit_path",
		Target:  &r.flagAuditPath,
		Default: "",
	})
	config.AuditPath = r.flagAuditPath

	r.setStringFlag(f, config.CAPEMFile, &StringVar{
		Name:    "ca_pem_file",
		EnvVar:  "VAULT_CACERT",
		Target:  &r.flagCAPEMFile,
		Default: "",
	})
	config.CAPEMFile = r.flagCAPEMFile

	r.setStringFlag(f, config.ClusterJSON, &StringVar{
		Name:    "cluster_json",
		Target:  &r.flagClusterJson,
		Default: "",
	})
	config.ClusterJSON = r.flagClusterJson

	r.setBoolFlag(f, config.Cleanup, &BoolVar{
		Name:    "cleanup",
		Target:  &r.flagCleanup,
		Default: false,
	})
	config.Cleanup = r.flagCleanup

	r.setBoolFlag(f, config.RandomMounts, &BoolVar{
		Name:    "random_mounts",
		Target:  &r.flagRandomMounts,
		Default: false,
	})
	config.RandomMounts = r.flagRandomMounts

	r.setStringFlag(f, config.LogLevel, &StringVar{
		Name:    "log_level",
		Target:  &r.flagLogLevel,
		Default: "INFO",
		EnvVar:  "VAULT_BENCHMARK_LOG_LEVEL",
	})

	config.LogLevel = r.flagLogLevel
}

func (r *RunCommand) setBoolFlag(f *FlagSets, configVal bool, fVar *BoolVar) {
	var isFlagSet bool
	f.Visit(func(f *flag.Flag) {
		if f.Name == fVar.Name {
			isFlagSet = true
		}
	})

	flagEnvValue, flagEnvSet := os.LookupEnv(fVar.EnvVar)
	switch {
	case isFlagSet:
		// Don't do anything as the flag is already set from the command line
	case flagEnvSet:
		// Use value from env var
		*fVar.Target = flagEnvValue != ""
	case configVal:
		// Use value from config
		*fVar.Target = configVal
	default:
		// Use the default value
		*fVar.Target = fVar.Default
	}
}

func (r *RunCommand) setStringFlag(f *FlagSets, configVal string, fVar *StringVar) {
	var isFlagSet bool
	f.Visit(func(f *flag.Flag) {
		if f.Name == fVar.Name {
			isFlagSet = true
		}
	})

	flagEnvValue, flagEnvSet := os.LookupEnv(fVar.EnvVar)
	switch {
	case isFlagSet:
		// Don't do anything as the flag is already set from the command line
	case flagEnvSet:
		// Use value from env var
		*fVar.Target = flagEnvValue
	case configVal != "":
		// Use value from config
		*fVar.Target = configVal
	default:
		// Use the default value
		*fVar.Target = fVar.Default
	}
}

func (r *RunCommand) setIntFlag(f *FlagSets, configVal int, fVar *IntVar) {
	var isFlagSet bool
	f.Visit(func(f *flag.Flag) {
		if f.Name == fVar.Name {
			isFlagSet = true
		}
	})

	flagEnvValue, flagEnvSet := os.LookupEnv(fVar.EnvVar)
	switch {
	case isFlagSet:
		// Don't do anything as the flag is already set from the command line
	case flagEnvSet:
		// Use value from env var
		tVal, err := strconv.Atoi(flagEnvValue)
		if err != nil {
			return
		}
		*fVar.Target = tVal
	case configVal != 0:
		*fVar.Target = configVal
	default:
		// Use the default value
		*fVar.Target = fVar.Default
	}
}

func (r *RunCommand) setDurationFlag(f *FlagSets, configVal string, fVar *DurationVar) {
	var isFlagSet bool
	f.Visit(func(f *flag.Flag) {
		if f.Name == fVar.Name {
			isFlagSet = true
		}
	})

	flagEnvValue, flagEnvSet := os.LookupEnv(fVar.EnvVar)
	switch {
	case isFlagSet:
		// Don't do anything as the flag is already set from the command line
	case flagEnvSet:
		// Use value from env var
		tVal, err := time.ParseDuration(flagEnvValue)
		if err != nil {
			return
		}
		*fVar.Target = tVal
	case configVal != "":
		tVal, err := time.ParseDuration(configVal)
		if err != nil {
			return
		}
		*fVar.Target = tVal
	default:
		// Use the default value
		*fVar.Target = fVar.Default
	}
}
