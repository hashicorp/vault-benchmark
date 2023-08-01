# GCP Secrets Engine Benchmark (`gcp_secret`)
This benchmark will test the dynamic generation of GCP access token and service account key credentials.

## Benchmark Configuration Parameters

### GCP Configuration (`config`)
- `credentials` (`string: <required>`) - JSON credentials (either file contents or '@path/to/file')
  See docs for [alternative ways](https://developer.hashicorp.com/vault/docs/secrets/gcp#setup) to pass in to this parameter, as well as the
  [required permissions](https://developer.hashicorp.com/vault/docs/secrets/gcp#required-permissions). This value can also be provided with the `VAULT_BENCHMARK_GCP_CREDENTIALS` environment variable. 
- `ttl` (`string:"0s"`) – Specifies default config TTL for long-lived credentials
  (i.e. service account keys). Uses [duration format strings](https://developer.hashicorp.com/vault/docs/concepts/duration-format).
- `max_ttl` (`string:"0s"`)– Specifies the maximum config TTL for long-lived credentials
  (i.e. service account keys). Uses [duration format strings](https://developer.hashicorp.com/vault/docs/concepts/duration-format).

### GCP Roleset (`roleset`)
- `name` (`string: "benchmark-roleset"`): Name of the role.
- `secret_type` (`string: "access_token"`): Type of secret generated for this role set. Accepted values: `access_token`, `service_account_key`. 
- `project` (`string: <required>`): Name of the GCP project that this roleset's service account will belong to. 
- `bindings` (`string: <required>`): Bindings configuration string (expects HCL or JSON format in raw or base64-encoded string). This value can also be provided with the `VAULT_BENCHMARK_GCP_BINDINGS` environment variable. 
- `token_scopes` (`array: []`): List of OAuth scopes to assign to `access_token` secrets generated under this role set (`access_token` role sets only)

## Example HCL
## Example Usage (generating an oauth2 access token)
```hcl
test "gcp_secret" "gcp_secret1" {
  weight = 100
  config {
    gcp {
      credentials = "@VaultServiceAccountKey.json"
    }

    roleset {
      name    = "gcp-secrets-roleset"
      project = "<project_id>"
      bindings = "@gcpbindings.hcl" 
      token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    }
  }
}
```

```bash
$ vault-benchmark run -config=config.hcl
2023-07-31T09:30:59.723-0500 [INFO]  vault-benchmark: setting up targets
2023-07-31T09:31:02.290-0500 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2023-07-31T09:31:12.364-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op           count  rate        throughput  mean         95th%        99th%       successRatio
gcp_secret1  3647   364.508644  362.029238  27.450306ms  39.522725ms  88.93587ms  100.00%
```

## Example Usage (generating a service account key)
```
rps = "1"

test "gcp_secret" "gcp_secret1" {
  weight = 100
  config {
    gcp {
    //   credentials = "@VaultServiceAccountKeyNew.json"
    }

    roleset {
      name    = "gcp-secrets-roleset"
      project = "hc-5a8eb1bf5cb84ac28a118b4f59a"
      secret_type = "service_account_key"
      bindings = "@gcpbindings.hcl" 
    //   token_scopes = ["access_token"]
    }
  }
}
```

```bash
$ vault-benchmark run -config=config.hcl
2023-07-31T09:32:16.964-0500 [INFO]  vault-benchmark: setting up targets
2023-07-31T09:32:18.896-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-07-31T09:32:21.503-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op           count  rate      throughput  mean          95th%         99th%         successRatio
gcp_secret1  2      1.999662  1.246645    559.547125ms  604.136792ms  604.136792ms  100.00%
```