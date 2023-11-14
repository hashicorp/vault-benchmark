# Kubernetes Auth Benchmark

This benchmark will test Vault authentication using the Kubernetes Auth method. In order to use this test, configuration for the target Kubernetes cluster must be provided as part of the configuration. The primary required field is `kubernetes_host`. A role config also needs to be passed with the primary required fields being `name`, `bound_service_account_names`, and `bound_service_account_namespaces`. Included is an example `benchmark-vault-job.yaml` file which can be applied to use the vault-benchmark image in a Kubernetes cluster. This example assumes a Vault cluster deployed in a Kubernetes environment based on our [Vault Installation to Minikube via Helm with Integrated Storage](https://learn.hashicorp.com/tutorials/vault/kubernetes-minikube-raft?in=vault/kubernetes) learn guide. This file can be edited to suit a specific deployment methodology. Below is the ConfigMap snippet showing example configuration:

## Test Parameters

### Auth Configuration `auth`

- `kubernetes_host` `(string: <required>)` - Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.
- `kubernetes_ca_cert` `(string: "")` - PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API. NOTE: Every line must end with a newline: `\n`
  If not set, the local CA cert will be used if running in a Kubernetes pod.
- `token_reviewer_jwt` `(string: "")` - A service account JWT used to access the TokenReview
  API to validate other JWTs during login. If not set,
  the local service account token is used if running in a Kubernetes pod, otherwise
  the JWT submitted in the login payload will be used to access the Kubernetes TokenReview API.
- `pem_keys` `(array: [])` - Optional list of PEM-formatted public keys or certificates
  used to verify the signatures of Kubernetes service account
  JWTs. If a certificate is given, its public key will be
  extracted. Not every installation of Kubernetes exposes these
  keys.
- `disable_local_ca_jwt` `(bool: false)` - Disable defaulting to the local CA cert and service account JWT when running in a Kubernetes pod.

### Deprecated Parameters

-> The following fields have been deprecated and will be removed in a future release:

- `disable_iss_validation` `(bool: true)` **Deprecated** Disable JWT issuer validation. Allows to skip ISS validation.

- `issuer` `(string: "")` **Deprecated** Optional JWT issuer. If no issuer is specified, then this plugin will use `kubernetes/serviceaccount` as the default issuer.
See [these instructions](https://developer.hashicorp.com/vault/docs/auth/kubernetes#discovering-the-service-account-issuer) for looking up the issuer for a given Kubernetes cluster.

### Caveats

If Vault is running in a Kubernetes Pod, the `kubernetes_ca_cert` and
`token_reviewer_jwt` parameters will automatically default to the local CA cert
(`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`) and local service
account JWT (`/var/run/secrets/kubernetes.io/serviceaccount/token`). This
behavior may be disabled by setting `disable_local_ca_jwt` to `true`.

When Vault is running in a non-Kubernetes environment, either
`kubernetes_ca_cert` or `pem_keys` must be set by the user.

### Role Config `role`

- `name` `(string: <required>)` - Name of the role.
- `bound_service_account_names` `(array: <required>)` - List of service account
  names able to access this role. If set to "\*" all names are allowed.
- `bound_service_account_namespaces` `(array: <required>)` - List of namespaces
  allowed to access this role. If set to "\*" all namespaces are allowed.
- `audience` `(string: "")` - Optional Audience claim to verify in the JWT.
- `alias_name_source` `(string: "serviceaccount_uid")` - Configures how identity aliases are generated.
  Valid choices are: `serviceaccount_uid`, `serviceaccount_name`
  When `serviceaccount_uid` is specified, the machine generated UID from the service account will be used as the identity alias name.
  When `serviceaccount_name` is specified, the service account's namespace and name will be used as the identity alias name e.g `vault/vault-auth`.
  While it is strongly advised that you use `serviceaccount_uid`, you may also use `serviceaccount_name` in cases where
  you want to set the alias ahead of time, and the risks are mitigated or otherwise acceptable given your use case.
  It is very important to limit who is able to delete/create service accounts within a given cluster.
  See the [Create an Entity Alias](https://developer.hashicorp.com/vault/api-docs/secret/identity/entity-alias#create-an-entity-alias) document
  which further expands on the potential security implications mentioned above.
- `token_ttl` `(integer: 0 or string: "")` - The incremental lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_max_ttl` `(integer: 0 or string: "")` - The maximum lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_policies` `(array: [] or comma-delimited string: "")` - List of
  token policies to encode onto generated tokens. Depending on the auth method, this
  list may be supplemented by user/group/other values.
- `policies` `(array: [] or comma-delimited string: "")` - List of token
  policies to encode onto generated tokens. Depending on the auth method, this
  list may be supplemented by user/group/other values.

### Example vault-benchmark config map YAML

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-benchmark-configmap
data:
  k8s.hcl: |
    # Basic Benchmark config options
    vault_addr = "http://vault:8200"
    vault_token = "root"
    duration = "10s"
    report_mode = "terse"
    random_mounts = true
    cleanup = true

    test "kube_auth" "kube_auth_test1" {
      weight = 100
      config {
        auth {
          kubernetes_host = "https://kubernetes.default.svc"
        }
        role {
          name = "vault-benchmark-role"
          bound_service_account_names = ["vault-benchmark"]
          bound_service_account_namespaces = ["*"]
          token_max_ttl = "24h"
          token_ttl = "1h"
        }
      }
    }

```

## Example Usage

```bash
$ kubectl apply -f vault-benchmark-job.yaml
$ kubectl logs -f vault-benchmark-qzpw8
```

Please refer to the [Vault Kubernetes Auth Method](https://www.vaultproject.io/api-docs/auth/kubernetes) documentation for all available configuration options.
