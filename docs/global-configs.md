## Global Configuration Options

`-annotate` `(string: "")` - Comma-separated name=value pairs include in `bench_running` prometheus metric. Try name 'testname' for dashboard example.

`-audit_path` `(string: "")` - Path to file for audit log storage.

`-ca_pem_file` `(string: "")` - Path to PEM encoded CA file to verify external Vault. This can also be specified via the `VAULT_CACERT` environment variable.

`-cleanup` `(bool: false)` - Cleanup benchmark artifacts after run.

`-cluster_json` `(string: "")` - Path to cluster.json file

`-debug` `(bool: false)` - Run vault-benchmark in Debug mode. The default is false.

`-duration` `(string: "10s")` - Test Duration.

`-log_level` `(string: "INFO")` - Level to emit logs. Options are: INFO, WARN, DEBUG, TRACE. This can also be specified via the `VAULT_BENCHMARK_LOG_LEVEL` environment variable.

`-pprof_interval` `(string: "")` - Collection interval for vault debug pprof profiling.

`-random_mounts` `(bool: true)` - Use random mount names.

`-report_mode` `(string: "terse")` - Reporting Mode. Options are: terse, verbose, json.

`-rps` `(int: 0)` - Requests per second. Setting to 0 means as fast as possible.

`-vault_addr` `(string:"http://127.0.0.1:8200")` - Target Vault API Address. This can also be specified via the `VAULT_ADDR` environment variable.

`-vault_namespace` `(string:"")` - Vault Namespace to create test mounts. This can also be specified via the `VAULT_NAMESPACE` environment variable.

`-vault_token` `(string: required)` - Vault Token to be used for test setup. This can also be specified via the `VAULT_TOKEN` environment variable.

`-workers` `(int: 10)` - Number of workers The default is 10.
