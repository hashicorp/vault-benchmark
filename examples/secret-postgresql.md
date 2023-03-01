# PostgreSQL Secret Configuration Options

This benchmark will test the dynamic generation of PostgreSQL credentials. In order to use this test, configuration for the PostgreSQL instance must be provided as an HCL file with `postgresql_db_config` and `postgresql_role_config` included in the config block. The primary required fields are the `username` and `password` for the user configured in PostgreSQL for Vault to use, as well as the `connection_url` field that defines the address to be used as well as any other parameters that need to be passed via the URL. 


### Example Usage

```bash
$ benchmark-vault run -config=example-configs/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op              count  rate        throughput  mean         95th%        99th%        successRatio
approle_test_1  249    248.880537  239.605824  41.018154ms  52.821772ms  58.667201ms  100.00%
```
