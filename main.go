package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault-tools/benchmark-vault/benchmark_tests"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func init() {
	// This doesn't need to be in an init, just putting it here to call it out.
	rand.Seed(time.Now().UnixNano())
}

func main() {
	var (
		bvCoreConfig = flag.String("config", "", "benchmark vault configuration file location")
		// Vault related settings
		vaultAddr   = flag.String("vault_addr", "", "vault address, overrides VAULT_ADDR")
		clusterJson = flag.String("cluster_json", "", "path to cluster.json file")
		vaultToken  = flag.String("vault_token", "", "vault token, overrides VAULT_TOKEN")
		auditPath   = flag.String("audit_path", "", "when creating vault cluster, path to file for audit log")
		caPEMFile   = flag.String("ca_pem_file", "", "when using external vault with HTTPS, path to its CA file in PEM format")

		// benchmark-vault settings
		workers       = flag.Int("workers", 10, "number of workers aka virtual users")
		rps           = flag.Int("rps", 0, "requests per second, or 0 for as fast as we can")
		duration      = flag.Duration("duration", 10*time.Second, "test duration")
		reportMode    = flag.String("report_mode", "terse", "reporting mode: terse, verbose, json")
		pprofInterval = flag.Duration("pprof_interval", 0, "collection interval for vault debug pprof profiling")
		inputResults  = flag.Bool("input_results", false, "instead of running tests, read a JSON file from a previous test run")
		annotate      = flag.String("annotate", "", "comma-separated name=value pairs include in bench_running prometheus metric, try name 'testname' for dashboard example")
		debug         = flag.Bool("debug", false, "before running tests, execute each benchmark target and output request/response info")
		randomMounts  = flag.Bool("random_mounts", true, "use random mount names")
		cleanup       = flag.Bool("cleanup", false, "cleanup after test run")
	)

	flag.Parse()

	// Load config from File
	conf, err := LoadConfig(*bvCoreConfig)
	if err != nil {
		fmt.Println(err)
		return
	}

	// TODO: See how to neatly handle override flags withoout needing to manually
	// type out and handle every single flag. There probably won't be a lot, but
	// this would be nice to do dynamically.

	/*
		// Check if we have any override flags
		flag.Visit(func(f *flag.Flag) {
			// Walk all the keys of the config struct
			r := reflect.ValueOf(&conf).Elem()
			currField := r.FieldByName(f.Name)
			currField.Set(f.Value)
		})
	*/

	if (!conf.RandomMounts || !*randomMounts) && (conf.Cleanup || *cleanup) {
		log.Fatal("Cleanup can only be enabled when random mounts is enabled")
	}

	switch *reportMode {
	case "terse", "verbose", "json":
	default:
		log.Fatal("report_mode must be one of terse, verbose, or json")
	}

	// If input_results is true we're not running benchmarks, just transforming input results based on reportMode
	if *inputResults {
		rpt, err := benchmark_tests.FromReader(os.Stdin)
		if err != nil {
			log.Fatalf("error reading report: %v", err)
		}
		switch *reportMode {
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
	case *clusterJson != "" && *vaultAddr != "":
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
	case *vaultAddr != "":
		cluster.VaultAddrs = []string{*vaultAddr}
	case os.Getenv("VAULT_ADDR") != "":
		cluster.VaultAddrs = []string{os.Getenv("VAULT_ADDR")}
	default:
		log.Fatalf("must specify one of cluster_json, vault_addr, or $VAULT_ADDR")
	}

	switch {
	case *vaultToken != "":
		cluster.Token = *vaultToken
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
	if *annotate != "" {
		for _, kv := range strings.Split(*annotate, ",") {
			kvPair := strings.SplitN(kv, "=", 2)
			if len(kvPair) != 2 || kvPair[0] == "" {
				log.Fatalf("annotate should contain comma-separated list of name=value pairs, got: %s", *annotate)
			}
			annoLabels = append(annoLabels, kvPair[0])
			annoValues = append(annoValues, kvPair[1])
		}
	}

	var testRunning = prometheus.NewGaugeVec(prometheus.GaugeOpts{
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
	//var clientKey string
	for _, addr := range cluster.VaultAddrs {
		tlsCfg := &vaultapi.TLSConfig{}
		cfg := vaultapi.DefaultConfig()
		if *caPEMFile != "" {
			tlsCfg.CACert = *caPEMFile
		}
		/*
			if spec.PctCertLogin > 0 {
				// Create self-signed CA
				benchCA, err := vegeta.GenerateCA()
				if err != nil {
					log.Fatalf("error generating benchmark CA: %v", err)
				}

				// Generate Client cert for Cert Auth
				clientCert, clientKey, err = vegeta.GenerateCert(benchCA.Template, benchCA.Signer)
				if err != nil {
					log.Fatalf("error generating client cert: %v", err)
				}

				// Create X509 Key Pair
				keyPair, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
				if err != nil {
					log.Fatalf("error generating client key pair: %v", err)
				}
				cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{keyPair}
			}
		*/
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

	if *pprofInterval != 0 {
		_ = os.Setenv("VAULT_ADDR", cluster.VaultAddrs[0])
		_ = os.Setenv("VAULT_TOKEN", cluster.Token)
		if *caPEMFile != "" {
			_ = os.Setenv("VAULT_CACERT", *caPEMFile)
		}
		cmd := exec.Command("vault", "debug", "-duration", (2 * *duration).String(),
			"-interval", pprofInterval.String(), "-compress=false")
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
	tm, err := benchmark_tests.BuildTargets(conf.Tests, clients[0], caPEM, clientCert, conf.RandomMounts)
	if err != nil {
		log.Fatalf("target setup failed: %v", err)
	}

	var l sync.Mutex
	results := make(map[string]*benchmark_tests.Reporter)
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

			fmt.Println("Starting benchmark tests. Will run for " + duration.String() + "...")
			rpt, err := benchmark_tests.Attack(tm, client, *duration, *rps, *workers)
			if err != nil {
				log.Fatal("attack error", err)
			}

			l.Lock()
			// TODO rethink how we present results when multiple nodes are attacked
			results[client.Address()] = rpt
			l.Unlock()

			fmt.Println("Benchmark complete!")
			if *cleanup {
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
		switch *reportMode {
		case "json":
			rpt.ReportJSON(os.Stdout)
		case "verbose":
			rpt.ReportVerbose(os.Stdout)
		default:
			rpt.ReportTerse(os.Stdout)
		}
		fmt.Println()
	}
}
