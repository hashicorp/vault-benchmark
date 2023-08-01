# Azure Authentication Credential Benchmark (`azure_auth`)

This benchmark tests the performance of logins using the Azure auth method.

## Benchmark Configuration Parameters

### Azure Authentication Configuration (`config`)`
- `tenant_id` `(string: <required>)` - The tenant id for the Azure Active Directory organization.
- `resource` `(string: <required>)` - The resource URL for the application registered in Azure Active Directory.
  The value is expected to match the audience (`aud` claim) of the [JWT](https://developer.hashicorp.com/vault/api-docs/auth/azure#jwt)
  provided to the login API. See the [resource](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token#get-a-token-using-http)
  parameter for how the audience is set when requesting a JWT access token from the Azure Instance Metadata Service (IMDS) endpoint.
- `environment` `(string: 'AzurePublicCloud')` - The Azure cloud environment. Valid values: AzurePublicCloud, AzureUSGovernmentCloud, AzureChinaCloud, AzureGermanCloud.
- `client_id` `(string: '')` - The client id for credentials to query the Azure APIs. Currently read permissions to query compute resources are required.
  This value can also be provided with the `VAULT_BENCHMARK_AZURE_CLIENT_ID` environment variable.
- `client_secret` `(string: '')` - The client secret for credentials to query the Azure APIs.
  This value can also be provided with the `VAULT_BENCHMARK_AZURE_CLIENT_SECRET` environment variable.

### Azure Role Configuration (`role`)`
- `name` `(string: <required>)` - Name of the role.
- `bound_service_principal_ids` `(array: [])` - The list of Service Principal IDs
  that login is restricted to.
- `bound_group_ids` `(array: [])` - The list of group ids that login is restricted
  to.
- `bound_locations` `(array: [])` - The list of locations that login is restricted to.
- `bound_subscription_ids` `(array: [])` - The list of subscription IDs that login
  is restricted to.
- `bound_resource_groups` `(array: [])` - The list of resource groups that
  login is restricted to.
- `bound_scale_sets` `(array: [])` - The list of scale set names that the
  login is restricted to.
- `token_ttl` `(integer: 0 or string: "")` - The incremental lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_max_ttl` `(integer: 0 or string: "")` - The maximum lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_policies` `(array: [] or comma-delimited string: "")` - List of
  token policies to encode onto generated tokens. Depending on the auth method, this
  list may be supplemented by user/group/other values.
- `policies` `(array: [] or comma-delimited string: "")` - DEPRECATED: Please
  use the `token_policies` parameter instead. List of token policies to encode
  onto generated tokens. Depending on the auth method, this list may be
  supplemented by user/group/other values.
- `token_bound_cidrs` `(array: [] or comma-delimited string: "")` - List of
  CIDR blocks; if set, specifies blocks of IP addresses which can authenticate
  successfully, and ties the resulting token to these blocks as well.
- `token_explicit_max_ttl` `(integer: 0 or string: "")` - If set, will encode
  an [explicit max
  TTL](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token. This is a hard cap even if `token_ttl` and `token_max_ttl`
  would otherwise allow a renewal.
- `token_no_default_policy` `(bool: false)` - If set, the `default` policy will
  not be set on generated tokens; otherwise it will be added to the policies set
  in `token_policies`.
- `token_num_uses` `(integer: 0)` - The maximum number of times a generated
  token may be used (within its lifetime); 0 means unlimited.
  If you require the token to have the ability to create child tokens,
  you will need to set this value to 0.
- `token_period` `(integer: 0 or string: "")` - The maximum allowed [period](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls) value when a periodic token is requested from this role.
- `token_type` `(string: "")` - The type of token that should be generated. Can
  be `service`, `batch`, or `default` to use the mount's tuned default (which
  unless changed will be `service` tokens). For token store roles, there are two
  additional possibilities: `default-service` and `default-batch` which specify
  the type to return unless the client requests a different type at generation
  time.

### Azure User Configuration (`user`)
- `role` `(string: <required>)` - Name of the role against which the login is being
  attempted.
- `jwt` `(string: <required>)` - Signed [JSON Web Token](https://tools.ietf.org/html/rfc7519) (JWT)
  from Azure MSI. See [Azure documentation](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token)
  for details on how to acquire a JWT access token through instance metadata. This value can also be provided with the `VAULT_BENCHMARK_AZURE_JWT` environment variable.
- `subscription_id` `(string: <required>)` - The subscription ID for the machine that
  generated the MSI token. This information can be obtained through instance
  metadata.
- `resource_group_name` `(string: <required>)` - The resource group for the machine that
  generated the MSI token. This information can be obtained through instance
  metadata.
- `vm_name` `(string: "")` - The virtual machine name for the machine that
  generated the MSI token. This information can be obtained through instance
  metadata. If `vmss_name` is provided, this value is ignored.
- `vmss_name` `(string: "")` - The virtual machine scale set name for the machine
  that generated the MSI token. This information can be obtained through instance
  metadata.
- `resource_id` `(string: "")` - The fully qualified ID of the Azure resource that
  generated the MSI token, including the resource name and resource type. Use
  the format /subscriptions/{guid}/resourceGroups/{resource-group-name}/{resource-provider-namespace}/{resource-type}/{resource-name}.
  If `vm_name` or `vmss_name` is provided, this value is ignored.

## Example HCL

```hcl
test "azure_auth" "azure_auth" {
  weight = 100
  config {
    config {
      tenant_id     = "<tenant_id>"
      resource      = "https://management.azure.com/"
      client_id     = "client_id"
      client_secret = "client_secret"
    }

    role {
      policies               = ["dev", "prod"]
      bound_resource_groups  = ["resource_group"]
      bound_subscription_ids = ["subscription_id"]
    }

    user {
      resource_group_name = "resource_group_name"
      subscription_id     = "subscription_id"
      vm_name             = "vm_name"
      jwt                 = "jwt"
    }
  }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-07-31T21:00:53.995-0500 [INFO]  vault-benchmark: setting up targets
2023-07-31T21:00:54.012-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-07-31T21:00:57.172-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op          count  rate      throughput  mean          95th%        99th%         successRatio
azure_auth  19     9.377571  6.013464    1.488866416s  2.10584931s  2.171915292s  100.00%
```
