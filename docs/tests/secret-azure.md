# Azure Secrets Engine Benchmark (`azure_secret`)
This benchmark will test the dynamic generation of Azure credentials.

## Benchmark Configuration Parameters

### Azure Configuration (`azure`)
- `subscription_id` (`string: <required>`) - The subscription id for the Azure Active Directory.
  This value can also be provided with the `VAULT_BENCHMARK_SUBSCRIPTION_ID` environment variable.
- `tenant_id` (`string: <required>`) - The tenant id for the Azure Active Directory.
  This value can also be provided with the `VAULT_BENCHMARK_TENANT_ID` environment variable.
- `client_id` (`string:""`) - The OAuth2 client id to connect to Azure. This value can also be provided
  with the `VAULT_BENCHMARK_CLIENT_ID` environment variable. See [authentication](https://developer.hashicorp.com/vault/docs/secrets/azure#authentication) for more details.
- `client_secret` (`string:""`) - The OAuth2 client secret to connect to Azure. This value can also be
  provided with the `VAULT_BENCHMARK_CLIENT_SECRET` environment variable. See [authentication](https://developer.hashicorp.com/vault/docs/secrets/azure#authentication) for more details.
- `environment` (`string:""`) - The Azure environment. This value can also be provided with the `VAULT_BENCHMARK_ENVIRONMENT`
  environment variable. If not specified, Vault will use Azure Public Cloud.
- `password_policy` `(string: "")` - Specifies a [password policy](https://developer.hashicorp.com/vault/docs/concepts/password-policies) to
  use when creating dynamic credentials. Defaults to generating an alphanumeric password if not set.
- `root_password_ttl` `(string: "182d")` - Specifies how long the root password is valid for in Azure when
  rotate-root generates a new client secret. Uses [duration format strings](https://developer.hashicorp.com/vault/docs/concepts/duration-format).

### Azure Role (`role`)
- `role` (`string: "benchmark-role"`) - Name of role.
- `azure_roles` (`string: ""`) - List of Azure roles to be assigned to the generated service
  principal. The array must be in JSON format, properly escaped as a string. See [roles docs](https://developer.hashicorp.com/vault/docs/secrets/azure#roles)
  for details on role definition.
- `azure_groups` (`string: ""`) - List of Azure groups that the generated service principal will be
  assigned to. The array must be in JSON format, properly escaped as a string. See [groups docs](https://developer.hashicorp.com/vault/docs/secrets/azure#azure-groups)
  for more details.
- `application_object_id` (`string: ""`) - Application Object ID for an existing service principal that will
  be used instead of creating dynamic service principals. If present, `azure_roles` will be ignored. See
  [roles docs](https://developer.hashicorp.com/vault/docs/secrets/azure#roles) for details on role definition.
- `persist_app` (`bool: "false"`) – If set to true, persists the created service principal and application for the lifetime of the role.
 Useful for when the Service Principal needs to maintain ownership of objects it creates
- `ttl` (`string: ""`) – Specifies the default TTL for service principals generated using this role.
  Accepts time suffixed strings ("1h") or an integer number of seconds. Defaults to the system/engine default TTL time.
- `max_ttl` (`string: ""`) – Specifies the maximum TTL for service principals generated using this role. Accepts time
  suffixed strings ("1h") or an integer number of seconds. Defaults to the system/engine max TTL time.
- `permanently_delete` (`bool: false`) - Specifies whether to permanently delete Applications and Service Principals that are dynamically
  created by Vault. If `application_object_id` is present, `permanently_delete` must be `false`.

## Example HCL

```hcl
test "azure_secret" "azure_secret1" {
    weight = 100
    config {
        azure {
            subscription_id = "subscription_id"
            tenant_id = "tenant_id"
            client_id = "client_id"
            client_secret = "client_secret"
        }

        role {
            ttl="1h"
            application_object_id="application_object_id"
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-07-17T11:58:45.488-0500 [INFO]  vault-benchmark: setting up targets
2023-07-17T11:58:46.039-0500 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2023-07-17T11:58:59.040-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op             count  rate      throughput  mean          95th%         99th%         successRatio
azure_secret1  47     4.602720  3.615952    2.495158143s  2.854567126s  3.008034917s  100.00%
```
