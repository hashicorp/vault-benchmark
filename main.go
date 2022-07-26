package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	_ "net/http/pprof"

	"github.com/hashicorp/vault-tools/benchmark-vault/vegeta"
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

		pkiConfigJSON            = flag.String("pki_config_json", "", "when specified, path to PKI benchmark configuration JSON file to use")
		sshCaConfigJSON          = flag.String("ssh_ca_config_json", "", "when specified, path to SSH CA benchmark configuration JSON file to use")
		transitSignConfigJSON    = flag.String("transit_sign_config_json", "", "when specified, path to Transit sign benchmark configuration JSON file to use")
		transitVerifyConfigJSON  = flag.String("transit_verify_config_json", "", "when specified, path to Transit verify benchmark configuration JSON file to use")
		transitEncryptConfigJSON = flag.String("transit_encrypt_config_json", "", "when specified, path to Transit encrypt benchmark configuration JSON file to use")
		transitDecryptConfigJSON = flag.String("transit_decrypt_config_json", "", "when specified, path to Transit decrypt benchmark configuration JSON file to use")
	)

	// test-related settings
	var spec = vegeta.TestSpecification{RandomMounts: true}
	flag.IntVar(&spec.NumKVs, "numkvs", 1000, "num KVs to use for KV operations")
	flag.IntVar(&spec.KVSize, "kvsize", 1, "num KVs to use for KV operations")
	flag.DurationVar(&spec.TokenTTL, "token_ttl", time.Hour, "ttl to use for logins")
	flag.IntVar(&spec.PctKvv1Write, "pct_kvv1_write", 0, "percent of requests that are kvv1 writes")
	flag.IntVar(&spec.PctKvv1Read, "pct_kvv1_read", 0, "percent of requests that are kvv1 reads")
	flag.IntVar(&spec.PctKvv2Write, "pct_kvv2_write", 0, "percent of requests that are kvv2 writes")
	flag.IntVar(&spec.PctKvv2Read, "pct_kvv2_read", 0, "percent of requests that are kvv2 reads")
	flag.IntVar(&spec.PctApproleLogin, "pct_approle_login", 0, "percent of requests that are approle logins")
	flag.IntVar(&spec.PctCertLogin, "pct_cert_login", 0, "percent of requests that are cert logins")
	flag.IntVar(&spec.PctPkiIssue, "pct_pki_issue", 0, "percent of requests that are pki issue certs")
	flag.IntVar(&spec.PctSshCaIssue, "pct_ssh_ca_issue", 0, "percent of requests that are ssh issue certs")
	flag.IntVar(&spec.PctHAStatus, "pct_ha_status", 0, "percent of requests that are ha status requests (/sys/ha-status)")
	flag.IntVar(&spec.PctSealStatus, "pct_seal_status", 0, "percent of requests that are seal status requests (/sys/seal-status)")
	flag.IntVar(&spec.PctMetrics, "pct_metrics", 0, "percent of requests that are read requests to metrics (/sys/metrics)")
	flag.IntVar(&spec.PctTransitSign, "pct_transit_sign", 0, "percent of requests that are sign requests to transit")
	flag.IntVar(&spec.PctTransitVerify, "pct_transit_verify", 0, "percent of requests that are verify requests to transit")
	flag.IntVar(&spec.PctTransitEncrypt, "pct_transit_encrypt", 0, "percent of requests that are encrypt requests to transit")
	flag.IntVar(&spec.PctTransitDecrypt, "pct_transit_decrypt", 0, "percent of requests that are decrypt requests to transit")

	// Config Options
	flag.DurationVar(&spec.PkiConfig.SetupDelay, "pki_setup_delay", 50*time.Millisecond, "When running PKI tests, delay after creating mount before attempting issuer creation")
	flag.DurationVar(&spec.SshCaConfig.SetupDelay, "ssh_ca_setup_delay", 50*time.Millisecond, "When running SSH CA tests, delay after creating mount before attempting issuer creation")
	flag.DurationVar(&spec.TransitSignConfig.SetupDelay, "transit_sign_setup_delay", 50*time.Millisecond, "When running Transit sign tests, delay after creating mount before attempting key creation")
	flag.DurationVar(&spec.TransitVerifyConfig.SetupDelay, "transit_verify_setup_delay", 50*time.Millisecond, "When running Transit verify tests, delay after creating mount before attempting key creation")
	flag.DurationVar(&spec.TransitEncryptConfig.SetupDelay, "transit_encrypt_setup_delay", 50*time.Millisecond, "When running Transit encrypt tests, delay after creating mount before attempting key creation")
	flag.DurationVar(&spec.TransitDecryptConfig.SetupDelay, "transit_decrypt_setup_delay", 50*time.Millisecond, "When running Transit decrypt tests, delay after creating mount before attempting key creation")

	flag.Parse()

	if err := spec.PkiConfig.FromJSON(*pkiConfigJSON); err != nil {
		log.Fatalf("unable to parse PKI config at %v: %v", *pkiConfigJSON, err)
	}

	if err := spec.SshCaConfig.FromJSON(*sshCaConfigJSON); err != nil {
		log.Fatalf("unable to parse SSH CA config at %v: %v", *sshCaConfigJSON, err)
	}

	if err := spec.TransitSignConfig.FromJSON(*transitSignConfigJSON); err != nil {
		log.Fatalf("unable to parse Transit sign config at %v: %v", *transitSignConfigJSON, err)
	}

	if err := spec.TransitVerifyConfig.FromJSON(*transitVerifyConfigJSON); err != nil {
		log.Fatalf("unable to parse Transit verify config at %v: %v", *transitVerifyConfigJSON, err)
	}

	if err := spec.TransitEncryptConfig.FromJSON(*transitEncryptConfigJSON); err != nil {
		log.Fatalf("unable to parse Transit encrypt config at %v: %v", *transitEncryptConfigJSON, err)
	}

	if err := spec.TransitDecryptConfig.FromJSON(*transitDecryptConfigJSON); err != nil {
		log.Fatalf("unable to parse Transit decrypt config at %v: %v", *transitDecryptConfigJSON, err)
	}

	switch *reportMode {
	case "terse", "verbose", "json":
	default:
		log.Fatal("report_mode must be one of terse, verbose, or json")
	}

	// If input_results is true we're not running benchmarks, just transforming input results based on reportMode
	if *inputResults {
		rpt, err := vegeta.FromReader(os.Stdin)
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
		b, err := ioutil.ReadFile(*clusterJson)
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
	var clientCert, clientKey string
	for _, addr := range cluster.VaultAddrs {
		tlsCfg := &vaultapi.TLSConfig{}
		cfg := vaultapi.DefaultConfig()
		if *caPEMFile != "" {
			tlsCfg.CACert = *caPEMFile
		}
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
		b, err := ioutil.ReadFile(*caPEMFile)
		if err != nil {
			log.Fatal(err)
		}
		caPEM = string(b)
	}

	testRunning.WithLabelValues(annoValues...).Set(1)
	tm, err := vegeta.BuildTargets(spec, clients[0], caPEM, clientCert)
	if err != nil {
		log.Fatalf("target setup failed, did you specify -pct arguments? error: %v", err)
	}

	var l sync.Mutex
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

			rpt, err := vegeta.Attack(tm, client, *duration, *rps, *workers)
			if err != nil {
				log.Fatal("attack error", err)
			}

			l.Lock()
			// TODO rethink how we present results when multiple nodes are attacked
			fmt.Println(client.Address())
			switch *reportMode {
			case "json":
				rpt.ReportJSON(os.Stdout)
			case "verbose":
				rpt.ReportVerbose(os.Stdout)
			default:
				rpt.ReportTerse(os.Stdout)
			}
			fmt.Println()
			l.Unlock()
		}(client)
	}
	testRunning.WithLabelValues(annoValues...).Set(0)

	wg.Wait()
}
