# GCP Secrets Engine Benchmark (`gcp_secret`)
This benchmark will test the creation of a unique OAuth token for an impersonated GCP service account.

## Benchmark Configuration Parameters

### GCP Impersonation Configuration (`config`)
- `credentials` (`string: <required>`) - JSON credentials (either file contents or '@path/to/file')
  See docs for [alternative ways](https://developer.hashicorp.com/vault/docs/secrets/gcp#setup) to pass in to this parameter, as well as the
  [required permissions](https://developer.hashicorp.com/vault/docs/secrets/gcp#required-permissions). This value can also be provided with the `VAULT_BENCHMARK_GCP_CREDENTIALS` environment variable. 
- `ttl` (`string:"0s"`) – Specifies default config TTL for long-lived credentials
  (i.e. service account keys). Uses [duration format strings](https://developer.hashicorp.com/vault/docs/concepts/duration-format).
- `max_ttl` (`string:"0s"`)– Specifies the maximum config TTL for long-lived credentials
  (i.e. service account keys). Uses [duration format strings](https://developer.hashicorp.com/vault/docs/concepts/duration-format).

### GCP Impersonation (`impersonate`)
- `name` (`string: "benchmark-gcp-impersonation"`): Name of the impersonated account. Cannot be updated.
- `service_account_email` (`string: <required>`): Email of the GCP service account to
  manage. Cannot be updated. This value can also be provided with the `VAULT_BENCHMARK_GCP_SERVICE_ACCOUNT_EMAIL` environment variable. 
- `token_scopes` (`array: []`): List of OAuth scopes to assign to access tokens
  generated under this impersonation account.
- `ttl` (`duration: ""`): Lifetime of the token generated. Defaults to 1 hour and
  is limited to a maximum of 12 hours. Uses [duration format strings](https://developer.hashicorp.com/vault/docs/concepts/duration-format).


## Example HCL
## Example Usage (generating an oauth2 access token)
```hcl
test "gcp_impersonation_secret" "gcp_secret1" {
  weight = 100
  config {
    gcp {
      credentials = "@/accountkey.json"
    }

    impersonate {
      name                  = "benchmark-impersonate"
      service_account_email = "service_account@.iam.gserviceaccount.com"
      token_scopes = ["https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/compute"]
    }
  }
}
```

```bash
$ vault-benchmark run -config=config.hcl
2023-08-04T11:40:05.274-0500 [INFO]  vault-benchmark: setting up targets
2023-08-04T11:40:05.757-0500 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2023-08-04T11:40:15.762-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op           count  rate      throughput  mean        95th%       99th%       successRatio
gcp_secret1  10     1.111245  1.110902    3.851262ms  6.247583ms  6.247583ms  100.00%
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
      project = "<project-id>"
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