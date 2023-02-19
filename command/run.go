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

	"github.com/hashicorp/vault-tools/benchmark-vault/benchmarktests"
	vbConfig "github.com/hashicorp/vault-tools/benchmark-vault/config"
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

	// Vault related settings
	clusterJson = flag.String("cluster_json", "", "path to cluster.json file")
)

type RunCommand struct {
	*BaseCommand
	flagVaultAddr        string
	flagVaultToken       string
	flagAuditPath        string
	flagVBCoreConfigPath string
	flagCAPEMFile        string
	flagWorkers          int
	flagRPS              int
	flagDuration         time.Duration
	flagReportMode       string
	flagPPROFInterval    time.Duration
	flagAnnotate         string
	flagRandomMounts     bool
	flagCleanup          bool
	flagDebug            bool
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
	set := r.flagSet(FlagSetNone)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:    "vault_addr",
		EnvVar:  "VAULT_ADDR",
		Target:  &r.flagVaultAddr,
		Default: "https://127.0.0.1:8200",
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

	f.BoolVar(&BoolVar{
		Name:    "debug",
		Target:  &r.flagDebug,
		Default: false,
		Usage:   "Run vault-benchmark in Debug mode.",
	})

	// Add any additional flags from tests
	for _, vbTest := range benchmarktests.TestList {
		vbTest().Flags(f.mainSet)
	}

	return set
}

func (r *RunCommand) Run(args []string) int {
	f := r.Flags()

	if err := f.Parse(args); err != nil {
		r.UI.Error(err.Error())
		return 1
	}

	if r.flagVBCoreConfigPath == "" {
		r.UI.Error("no config file location passed")
		return 1
	}

	conf := vbConfig.NewVaultBenchmarkCoreConfig()

	// Load config from File
	err := conf.LoadConfig(r.flagVBCoreConfigPath)
	if err != nil {
		r.UI.Error(err.Error())
		return 1
	}

	r.applyConfigOverrides(f, conf)

	// Parse Duration from configuration string
	parsedDuration, err := time.ParseDuration(conf.Duration)
	if err != nil {
		r.UI.Error(fmt.Sprintf("error parsing test duration from configuration: %v", err))
	}

	// Parse pprof Interval from configuration string
	var parsedPPROFinterval time.Duration
	if conf.PPROFInterval != "" {
		parsedPPROFinterval, err = time.ParseDuration(conf.PPROFInterval)
		if err != nil {
			r.UI.Error(fmt.Sprintf("error parsing pprof interval from configuration: %v", err))
			return 1
		}
	}

	if (!conf.RandomMounts) && (conf.Cleanup) {
		r.UI.Error("Cleanup can only be enabled when random mounts is enabled")
		return 1
	}

	switch conf.ReportMode {
	case "terse", "verbose", "json":
	default:
		r.UI.Error("report_mode must be one of terse, verbose, or json")
	}

	var cluster struct {
		Token      string   `json:"token"`
		VaultAddrs []string `json:"vault_addrs"`
	}
	switch {
	case *clusterJson != "" && conf.VaultAddr != "":
		r.UI.Error("cannot specify both cluster_json and vault_addr")
		return 1
	case *clusterJson != "":
		b, err := os.ReadFile(*clusterJson)
		if err != nil {
			r.UI.Error(fmt.Sprintf("error reading cluster_json file %q: %v", *clusterJson, err))
		}
		err = json.Unmarshal(b, &cluster)
		if err != nil {
			r.UI.Error(fmt.Sprintf("error decoding cluster_json file %q: %v", *clusterJson, err))
		}
	case conf.VaultAddr != "":
		cluster.VaultAddrs = []string{conf.VaultAddr}
	case os.Getenv("VAULT_ADDR") != "":
		cluster.VaultAddrs = []string{os.Getenv("VAULT_ADDR")}
	default:
		r.UI.Error("must specify one of cluster_json, vault_addr, or $VAULT_ADDR")
	}

	switch {
	case conf.VaultToken != "":
		cluster.Token = conf.VaultToken
	case cluster.Token == "" && os.Getenv("VAULT_TOKEN") != "":
		cluster.Token = os.Getenv("VAULT_TOKEN")
	}
	if cluster.Token == "" {
		r.UI.Error("must specify one of cluster_json, vault_token, or $VAULT_TOKEN")
		return 1
	}

	// Setup annotations and testRunning metric
	var annoLabels []string
	var annoValues []string
	if conf.Annotate != "" {
		for _, kv := range strings.Split(conf.Annotate, ",") {
			kvPair := strings.SplitN(kv, "=", 2)
			if len(kvPair) != 2 || kvPair[0] == "" {
				r.UI.Error(fmt.Sprintf("annotate should contain comma-separated list of name=value pairs, got: %s", conf.Annotate))
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
	var clientCert string
	// var clientKey string
	for _, addr := range cluster.VaultAddrs {
		tlsCfg := &vaultapi.TLSConfig{}
		cfg := vaultapi.DefaultConfig()
		if conf.CAPEMFile != "" {
			tlsCfg.CACert = conf.CAPEMFile
		}
		err := cfg.ConfigureTLS(tlsCfg)
		if err != nil {
			r.UI.Error(fmt.Sprintf("error creating vault client: %v", err))
			return 1
		}
		cfg.Address = addr
		client, err := vaultapi.NewClient(cfg)
		if err != nil {
			r.UI.Error(fmt.Sprintf("error creating vault client: %v", err))
			return 1
		}
		client.SetToken(cluster.Token)
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
				r.UI.Error(fmt.Sprintf("error running pprof: %v", err))
			}
			r.UI.Info(fmt.Sprintf("pprof: %s", out))
		}()

		defer func() {
			// We can't use CommandContext because that uses sigkill, and we
			// want the debug process to wrap things up and write indexes/etc.
			r.UI.Info("stopping pprof")
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
			r.UI.Error(fmt.Sprintf("error enabling audit device: %v", err))
			return 1
		}
	}

	var caPEM string
	if conf.CAPEMFile != "" {
		b, err := os.ReadFile(conf.CAPEMFile)
		if err != nil {
			r.UI.Error(err.Error())
			return 1
		}
		caPEM = string(b)
	}

	testRunning.WithLabelValues(annoValues...).Set(1)
	tm, err := benchmarktests.BuildTargets(conf.Tests, clients[0], caPEM, clientCert, conf.RandomMounts)
	if err != nil {
		r.UI.Error(fmt.Sprintf("target setup failed: %v", err))
		return 1
	}

	var l sync.Mutex
	results := make(map[string]*benchmarktests.Reporter)
	for _, client := range clients {
		wg.Add(1)
		go func(client *vaultapi.Client) {
			defer wg.Done()

			if r.flagDebug {
				l.Lock()
				fmt.Println("=== Debug Info ===")
				fmt.Printf("Client: %s\n", client.Address())
				tm.DebugInfo(client)
				l.Unlock()
			}

			fmt.Println("Starting benchmark tests. Will run for " + parsedDuration.String() + "...")
			rpt, err := benchmarktests.Attack(tm, client, parsedDuration, conf.RPS, conf.Workers)
			if err != nil {
				r.UI.Error(fmt.Sprint("attack error", err))
				os.Exit(1)
			}

			l.Lock()
			// TODO rethink how we present results when multiple nodes are attacked
			results[client.Address()] = rpt
			l.Unlock()

			fmt.Println("Benchmark complete!")
			if conf.Cleanup {
				fmt.Println("Cleaning up...")
				err := tm.Cleanup(client)
				if err != nil {
					r.UI.Error(fmt.Sprint("cleanup error", err))
				}
				if conf.AuditPath != "" {
					_, err := client.Logical().Delete("/sys/audit/bench-audit")
					if err != nil {
						r.UI.Error("Error disabling bench-audit audit device! This may require manual intervention.")
					}
				}
			}
		}(client)
	}
	testRunning.WithLabelValues(annoValues...).Set(0)

	wg.Wait()

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
