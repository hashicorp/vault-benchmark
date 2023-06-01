# Nomad Secrets Engine Benchmark

This benchmark will test the dynamic generation of Nomad credentials.

## Test Parameters

### Nomad Database Configuration `nomad`

#### NOTE: Ensure that the Nomad system has a limit high enough to support the number of roles you are creating.  More information can be found in the [Nomad Documentation](https://developer.hashicorp.com/nomad/docs/configuration#limits)

- `address` `(string: "")` – Specifies the address of the Nomad instance, provided as `"protocol://host:port"` like `"http://127.0.0.1:4646"`. This value can also be provided on individual calls with the NOMAD_ADDR environment variable.
- `token` `(string: "")` – Specifies the Nomad Management token to use. This value can also be provided on individual calls with the NOMAD_TOKEN environment variable.  This can also be provided via the `VAULT_BENCHMARK_NOMAD_TOKEN` environment variable.
- `max_token_name_length` `(int: <optional>)` – Specifies the maximum length to use for the name of the Nomad token generated with [Generate Credential](https://developer.hashicorp.com/vault/api-docs/secret/nomad#generate-credential). If omitted, `0` is used and ignored, defaulting to the max value allowed by the Nomad version. For Nomad versions 0.8.3 and earlier, the default is `64`. For Nomad version 0.8.4 and later, the default is `256`.
- `ca_cert` `(string: "")` - CA certificate to use when verifying Nomad server certificate, must be x509 PEM encoded.
- `client_cert` `(string: "")` - Client certificate used for Nomad's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_key.
- `client_key` `(string: "")` - Client key used for Nomad's TLS communication, must be x509 PEM encoded and if this is set you need to also set client_cert.

### Role Config `role`

- `name` `(string: "benchmark-role")` – Specifies the name of an existing role against which to create this Nomad tokens. This is part of the request URL.
- `policies` `(string: "")` – Comma separated list of Nomad policies the token is going to be created against. These need to be created beforehand in Nomad.
- `global` `(bool: "false")` – Specifies if the token should be global, as defined in the [Nomad Documentation](https://developer.hashicorp.com/nomad/tutorials/access-control#acl-tokens).
- `type` `(string: "client")` - Specifies the type of token to create when using this role. Valid values are `"client"` or `"management"`.

## Example Configuration

```hcl
test "nomad_secret" "nomad_test_1" {
    weight = 100
    config {
        nomad {
            address = "http://127.0.0.1:4646"
            token = "NOMAD_TOKEN"
        }
        role  {
            global = true
            type = "management"
        }
    }
}

```

### Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-06-01T09:41:27.096-0500 [INFO]  vault-benchmark: setting up targets
2023-06-01T09:41:27.102-0500 [INFO]  vault-benchmark: starting benchmarks: duration=5s
2023-06-01T09:41:32.311-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op            count  rate       throughput  mean          95th%         99th%         successRatio
nomad_test_1  177    35.057995  33.990891   290.850018ms  375.292712ms  451.573602ms  100.00%
```
