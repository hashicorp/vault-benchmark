package command

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"reflect"
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

	// notSetValue is a flag value for a not-set value
	notSetValue = "(not set)"
)

var (
	_ cli.Command = (*RunCommand)(nil)
	//_ cli.CommandAutocomplete = (*RunCommand)(nil)

	// Vault related settings
	clusterJson = flag.String("cluster_json", "", "path to cluster.json file")
	auditPath   = flag.String("audit_path", "", "when creating vault cluster, path to file for audit log")
	caPEMFile   = flag.String("ca_pem_file", "", "when using external vault with HTTPS, path to its CA file in PEM format")

	// benchmark-vault settings
	debug = flag.Bool("debug", false, "before running tests, execute each benchmark target and output request/response info")
)

type RunCommand struct {
	*BaseCommand
	flagVaultAddr        string
	flagVaultToken       string
	flagVBCoreConfigPath string
	flagWorkers          int
	flagRPS              int
	flagDuration         time.Duration
	flagReportMode       string
	flagPPROFInterval    time.Duration
	flagInputResults     bool
	flagAnnotate         string
	flagRandomMounts     bool
	flagCleanup          bool
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

	f.BoolVar(&BoolVar{
		Name:    "input_results",
		Target:  &r.flagInputResults,
		Default: false,
		Usage:   "Instead of running tests, read a JSON file from a previous test run.",
	})

	f.StringVar(&StringVar{
		Name:    "annotate",
		Target:  &r.flagAnnotate,
		Default: "",
		Usage:   "Comma-separated name=value pairs include in bench_running prometheus metric. Try name 'testname' for dashboard example.",
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

	// Pull in all flags from included tests
	flag.VisitAll(func(fl *flag.Flag) {
		flValType := reflect.TypeOf(fl.Value)
		baseValType := flValType.Elem()

		switch baseValType.Kind() {
		case reflect.String:
			f.StringVar(&StringVar{
				Name: fl.Name,
			})
		}
	})

	return set
}

func (r *RunCommand) Run(args []string) int {

	conf := vbConfig.NewVaultBenchmarkCoreConfig()
	flag.Parse()
	f := r.Flags()

	if err := f.Parse(args); err != nil {
		r.UI.Error(err.Error())
		return 1
	}

	// Load config from File
	err := conf.LoadConfig(r.flagVBCoreConfigPath)
	if err != nil {
		r.UI.Error(err.Error())
		return 1
	}

	// This feels fragile...
	// Check if we have any override flags
	err = benchmarktests.ConfigOverrides(conf)
	if err != nil {
		r.UI.Error(fmt.Sprintf("error overriding config options: %v", err))
	}

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
			log.Fatalf("error parsing pprof interval from configuration: %v", err)
		}
	}

	if (!conf.RandomMounts) && (conf.Cleanup) {
		log.Fatal("Cleanup can only be enabled when random mounts is enabled")
	}

	switch conf.ReportMode {
	case "terse", "verbose", "json":
	default:
		log.Fatal("report_mode must be one of terse, verbose, or json")
	}

	// If input_results is true we're not running benchmarks, just transforming input results based on reportMode
	if conf.InputResults {
		rpt, err := benchmarktests.FromReader(os.Stdin)
		if err != nil {
			log.Fatalf("error reading report: %v", err)
		}
		switch conf.ReportMode {
		case "json":
			err = fmt.Errorf("asked to report JSON on JSON input")
		case "terse":
			err = rpt.ReportTerse(os.Stdout)
		case "verbose":
			err = rpt.ReportVerbose(os.Stdout)
		}
		if err != nil {
			log.Fatalf("error writing report: %v", err)
		}

		os.Exit(0)
	}

	var cluster struct {
		Token      string   `json:"token"`
		VaultAddrs []string `json:"vault_addrs"`
	}
	switch {
	case *clusterJson != "" && conf.VaultAddr != "":
		log.Fatalf("cannot specify both cluster_json and vault_addr")
	case *clusterJson != "":
		b, err := os.ReadFile(*clusterJson)
		if err != nil {
			log.Fatalf("error reading cluster_json file %q: %v", *clusterJson, err)
		}
		err = json.Unmarshal(b, &cluster)
		if err != nil {
			log.Fatalf("error decoding cluster_json file %q: %v", *clusterJson, err)
		}
	case conf.VaultAddr != "":
		cluster.VaultAddrs = []string{conf.VaultAddr}
	case os.Getenv("VAULT_ADDR") != "":
		cluster.VaultAddrs = []string{os.Getenv("VAULT_ADDR")}
	default:
		log.Fatalf("must specify one of cluster_json, vault_addr, or $VAULT_ADDR")
	}

	switch {
	case conf.VaultToken != "":
		cluster.Token = conf.VaultToken
	case cluster.Token == "" && os.Getenv("VAULT_TOKEN") != "":
		cluster.Token = os.Getenv("VAULT_TOKEN")
	}
	if cluster.Token == "" {
		log.Fatal("must specify one of cluster_json, vault_token, or $VAULT_TOKEN")
	}

	if *caPEMFile == "" {
		*caPEMFile = os.Getenv("VAULT_CACERT")
	}

	// Setup annotations and testRunning metric
	var annoLabels []string
	var annoValues []string
	if conf.Annotate != "" {
		for _, kv := range strings.Split(conf.Annotate, ",") {
			kvPair := strings.SplitN(kv, "=", 2)
			if len(kvPair) != 2 || kvPair[0] == "" {
				log.Fatalf("annotate should contain comma-separated list of name=value pairs, got: %s", conf.Annotate)
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
		if *caPEMFile != "" {
			tlsCfg.CACert = *caPEMFile
		}
		err := cfg.ConfigureTLS(tlsCfg)
		if err != nil {
			log.Fatalf("error creating vault client: %v", err)
		}
		cfg.Address = addr
		client, err := vaultapi.NewClient(cfg)
		if err != nil {
			log.Fatalf("error creating vault client: %v", err)
		}
		client.SetToken(cluster.Token)
		clients = append(clients, client)
	}

	var wg sync.WaitGroup

	if parsedPPROFinterval.Seconds() != 0 {
		_ = os.Setenv("VAULT_ADDR", cluster.VaultAddrs[0])
		_ = os.Setenv("VAULT_TOKEN", cluster.Token)
		if *caPEMFile != "" {
			_ = os.Setenv("VAULT_CACERT", *caPEMFile)
		}
		cmd := exec.Command("vault", "debug", "-duration", (2 * parsedDuration).String(),
			"-interval", parsedPPROFinterval.String(), "-compress=false")
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("error running pprof: %v", err)
			}
			log.Printf("pprof: %s", out)
		}()

		defer func() {
			// We can't use CommandContext because that uses sigkill, and we
			// want the debug process to wrap things up and write indexes/etc.
			log.Println("stopping pprof")
			cmd.Process.Signal(os.Interrupt)
		}()
	}

	if *auditPath != "" {
		err := clients[0].Sys().EnableAuditWithOptions("bench-audit", &vaultapi.EnableAuditOptions{
			Type: "file",
			Options: map[string]string{
				"file_path": *auditPath,
			},
		})
		if err != nil {
			log.Fatalf("error enabling audit device: %v", err)
		}
	}

	var caPEM string
	if *caPEMFile != "" {
		b, err := os.ReadFile(*caPEMFile)
		if err != nil {
			log.Fatal(err)
		}
		caPEM = string(b)
	}

	testRunning.WithLabelValues(annoValues...).Set(1)
	tm, err := benchmarktests.BuildTargets(conf.Tests, clients[0], caPEM, clientCert, conf.RandomMounts)
	if err != nil {
		log.Fatalf("target setup failed: %v", err)
	}

	var l sync.Mutex
	results := make(map[string]*benchmarktests.Reporter)
	for _, client := range clients {
		wg.Add(1)
		go func(client *vaultapi.Client) {
			defer wg.Done()

			if *debug {
				l.Lock()
				fmt.Println("=== Debug Info ===")
				fmt.Printf("Client: %s\n", client.Address())
				tm.DebugInfo(client)
				l.Unlock()
			}

			fmt.Println("Starting benchmark tests. Will run for " + parsedDuration.String() + "...")
			rpt, err := benchmarktests.Attack(tm, client, parsedDuration, conf.RPS, conf.Workers)
			if err != nil {
				log.Fatal("attack error", err)
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
					log.Println("cleanup error", err)
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
