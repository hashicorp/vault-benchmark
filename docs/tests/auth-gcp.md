# Google Cloud Platform Auth Benchmark (`gcp_auth`)

This benchmark will test GC Authentication to Vault. The primary required fields are `credentials`, `name` and `type`.

## Test Parameters

### Auth Configuration `auth`
### Parameters
- `credentials` `(string: <required>)` - A JSON string containing the contents of a GCP
  service account credentials file. The service account associated with the credentials
  file must have the following [permissions](https://developer.hashicorp.com/vault/docs/auth/gcp#required-gcp-permissions).
  If this value is empty, Vault will try to use [Application Default Credentials][https://developers.google.com/identity/protocols/application-default-credentials]
  from the machine on which the Vault server is running.
- `iam_alias` `(string: "role_id")` - Must be either `unique_id` or `role_id`.
  If `unique_id` is specified, the service account's unique ID will be used for
  alias names during login. If `role_id` is specified, the ID of the Vault role
  will be used. Only used if role `type` is `iam`.
- `iam_metadata` `(string: "default")` - The metadata to include on the token
  returned by the `login` endpoint. This metadata will be added to both audit logs,
  and on the `iam_alias`. By default, it includes `project_id`, `role`,
  `service_account_id`, and `service_account_email`. To include no metadata,
  set to `""` via the CLI or `[]` via the API. To use only particular fields, select
  the explicit fields. To restore to defaults, send only a field of `default`.
  **Only select fields that will have a low rate of change** for your `iam_alias` because
  each change triggers a storage write and can have a performance impact at scale.
  Only used if role `type` is `iam`.
- `gce_alias` `(string: "role_id")` - Must be either `instance_id` or `role_id`.
  If `instance_id` is specified, the GCE instance ID will be used for alias names
  during login. If `role_id` is specified, the ID of the Vault role will be used.
  Only used if role `type` is `gce`.
- `gce_metadata` `(string: "default")` - The metadata to include on the token
  returned by the `login` endpoint. This metadata will be added to both audit logs,
  and on the `gce_alias`. By default, it includes `instance_creation_timestamp`,
  `instance_id`, `instance_name`, `project_id`, `project_number`, `role`,
  `service_account_id`, `service_account_email`, and `zone`. To include no metadata,
  set to `""` via the CLI or `[]` via the API. To use only particular fields, select
  the explicit fields. To restore to defaults, send only a field of `default`.
  **Only select fields that will have a low rate of change** for your `gce_alias` because
  each change triggers a storage write and can have a performance impact at scale.
  Only used if role `type` is `gce`.
- `custom_endpoint` `(map<string|string>: <optional>)` - Specifies overrides to
  [service endpoints](https://cloud.google.com/apis/design/glossary#api_service_endpoint)
  used when making API requests. This allows specific requests made during authentication
  to target alternative service endpoints for use in [Private Google Access](https://cloud.google.com/vpc/docs/configure-private-google-access)
  environments.

### Test User Config `role`
### Parameters
- `name` `(string: <required>)` - The name of the role.
- `type` `(string: <required>)` - The type of this role. Certain fields
  correspond to specific roles and will be rejected otherwise. Please see below
  for more information.
- `bound_service_accounts` `(array: <required for iam>)` - An array of
  service account emails or IDs that login is restricted to,
  either directly or through an associated instance. If set to
  `*`, all service accounts are allowed (you can bind this further using
  `bound_projects`.)
- `bound_projects` `(array: [])` - An array of GCP project IDs. Only entities
  belonging to this project can authenticate under the role.
- `add_group_aliases` `(bool: false)` - If true, any auth token
  generated under this token will have associated group aliases, namely
  `project-$PROJECT_ID`, `folder-$PROJECT_ID`, and `organization-$ORG_ID`
  for the entities project and all its folder or organization ancestors. This
  requires Vault to have IAM permission `resourcemanager.projects.get`.
- `token_bound_cidrs` `(array: [])` - List of
  CIDR blocks; if set, specifies blocks of IP addresses which can authenticate
  successfully, and ties the resulting token to these blocks as well.
- `token_explicit_max_ttl` `(string: "")` - If set, will encode
  an [explicit max
  TTL](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token. This is a hard cap even if `token_ttl` and `token_max_ttl`
  would otherwise allow a renewal.
- `token_max_ttl` `(string: "")` - The maximum lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_no_default_policy` `(bool: false)` - If set, the `default` policy will
  not be set on generated tokens; otherwise it will be added to the policies set
  in `token_policies`.
- `token_num_uses` `(integer: 0)` - The maximum number of times a generated
  token may be used (within its lifetime); 0 means unlimited.
  If you require the token to have the ability to create child tokens,
  you will need to set this value to 0.
- `token_period` `(string: "")` - The maximum allowed [period](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls) value when a periodic token is requested from this role.
- `token_type` `(string: "")` - The type of token that should be generated. Can
  be `service`, `batch`, or `default` to use the mount's tuned default (which
  unless changed will be `service` tokens). For token store roles, there are two
  additional possibilities: `default-service` and `default-batch` which specify
  the type to return unless the client requests a different type at generation
  time.
- `token_policies` `(array: [])` - List of
  token policies to encode onto generated tokens. Depending on the auth method, this
  list may be supplemented by user/group/other values.
- `token_ttl` `(string: "")` - The incremental lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.

#### `iam`-only Parameters
The following parameters are only valid when the role is of type `"iam"`:
- `max_jwt_exp` `(string: "15m")` - The number of seconds past the time of
  authentication that the login param JWT must expire within. For example, if a
  user attempts to login with a token that expires within an hour and this is
  set to 15 minutes, Vault will return an error prompting the user to create a
  new signed JWT with a shorter `exp`. The GCE metadata tokens currently do not
  allow the `exp` claim to be customized.
- `allow_gce_inference` `(bool: true)` - A flag to determine if this role should
  allow GCE instances to authenticate by inferring service accounts from the
  GCE identity metadata token.

#### `gce`-only Parameters
The following parameters are only valid when the role is of type `"gce"`:
- `bound_zones` `(array: [])`: The list of zones that a GCE instance must belong
  to in order to be authenticated. If `bound_instance_groups` is provided, it is
  assumed to be a zonal group and the group must belong to this zone.
- `bound_regions` `(array: [])`: The list of regions that a GCE instance must
  belong to in order to be authenticated. If `bound_instance_groups` is
  provided, it is assumed to be a regional group and the group must belong to
  this region. If `bound_zones` are provided, this attribute is ignored.
- `bound_instance_groups` `(array: [])`: The instance groups that an authorized
  instance must belong to in order to be authenticated. If specified, either
  `bound_zones` or `bound_regions` must be set too.
- `bound_labels` `(array: [])`: A comma-separated list of GCP labels formatted
  as "key:value" strings that must be set on authorized GCE instances. Because
  GCP labels are not currently ACL'd, we recommend that this be used in
  conjunction with other restrictions.

## Example HCL

```hcl
test "gcp_auth" "gcp_auth1" {
    weight = 100
    config {
        auth {
            credentials = "@VaultServiceAccountKey.json"
        }

        role {
            name="vault-iam-auth-role"
            type="iam"
            bound_service_accounts=["VaultServiceAccount2@hc-1.iam.gserviceaccount.com", "VaultServiceAccount@hc-2.iam.gserviceaccount.com"]
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=gcp.hcl
2023-07-10T18:45:34.066-0500 [INFO]  vault-benchmark: setting up targets
2023-07-10T18:45:34.375-0500 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2023-07-10T18:45:44.747-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op           count  rate      throughput  mean          95th%         99th%         successRatio
gcp_secret1  10     1.110981  1.067072    735.430229ms  1.148094333s  1.148094333s  100.00%
```
