# Kubernetes Secrets Engine Benchmark (`kubernetes_secret`)

This benchmark will test the dynamic generation of Kubernetes service account tokens.

## Test Parameters

### Kubernetes Configuration `kubernetes`

- `kubernetes_host` `(string: "https://kubernetes.default.svc")` – Kubernetes API URL to connect to. Must be specified if the standard pod environment variables `KUBERNETES_SERVICE_HOST` or `KUBERNETES_SERVICE_PORT_HTTPS` are not set.
- `kubernetes_ca_cert` `(string: "")` – PEM encoded CA certificate to verify the Kubernetes API server certificate. Defaults to the local pod's CA certificate at `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` if found, or otherwise the host's root CA set. This can also be provided via the `VAULT_BENCHMARK_KUBERNETES_CA_CERT` environment variable.
- `service_account_jwt` `(string: "")` – The JSON web token of the service account used by the secrets engine to manage Kubernetes credentials. Defaults to the local pod's JWT at `/var/run/secrets/kubernetes.io/serviceaccount/token` if found. This can also be provided via the `VAULT_BENCHMARK_KUBERNETES_SERVICE_ACCOUNT_JWT` environment variable.
- `disable_local_ca_jwt` `(bool: false)` – Disable defaulting to the local CA certificate and service account JWT when running in a Kubernetes pod.

### Role Configuration `role`

The Kubernetes secrets engine role can operate in one of 3 modes. Each successive mode generates more Kubernetes objects, and therefore requires more permissions for Vault's own Kubernetes service account:

1. **Generate a service account token for a pre-existing service account** - set `service_account_name`.
2. **Generate a service account and a token, and bind a pre-existing Kubernetes role** - set `kubernetes_role_name`.
3. **Generate a Kubernetes role, role binding, service account and token** - set `generated_role_rules`.

Only one of `service_account_name`, `kubernetes_role_name` or `generated_role_rules` can be set.

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create. This is specified as part of the URL.
- `allowed_kubernetes_namespaces` `(array: ["default"])` – The list of Kubernetes namespaces this role can generate credentials for. If set to `["*"]` all namespaces are allowed. If set with `allowed_kubernetes_namespace_selector`, the conditions are `OR`ed.
- `allowed_kubernetes_namespace_selector` `(string: "")` – A label selector for Kubernetes namespaces in which credentials can be generated. Accepts either a JSON or YAML object. The value should be of type LabelSelector. If set with `allowed_kubernetes_namespaces`, the conditions are `OR`ed.
- `token_max_ttl` `(string: "")` – The maximum TTL for generated Kubernetes tokens, specified in seconds or as a Go duration format string, e.g. `"1h"`. If not set or set to 0, the system default will be used.
- `token_default_ttl` `(string: "")` – The default TTL for generated Kubernetes tokens, specified in seconds or as a Go duration format string, e.g. `"1h"`. If not set or set to 0, the system default will be used.
- `token_default_audiences` `(string: "")` – The default intended audiences for generated Kubernetes tokens, specified by a comma separated string. e.g `"custom-audience-0,custom-audience-1"`. If not set or set to `""`, the Kubernetes cluster default for audiences of service account tokens will be used.
- `service_account_name` `(string: "")` – The pre-existing service account to generate tokens for. Mutually exclusive with all role parameters. If set, only a Kubernetes token will be created when credentials are requested.
- `kubernetes_role_name` `(string: "")` – The pre-existing Role or ClusterRole to bind a generated service account to. If set, Kubernetes token, service account, and role binding objects will be created when credentials are requested.
- `kubernetes_role_type` `(string: "Role")` – Specifies whether the Kubernetes role is a `Role` or `ClusterRole`.
- `kubernetes_role_ref_type` `(string: "")` – Optional value indicating whether the Kubernetes role referenced in the final RoleBinding is a Role or ClusterRole. When left blank, Vault uses the value from `kubernetes_role_type`.
- `generated_role_rules` `(string: "")` – The Role or ClusterRole rules to use when generating a role. Accepts either JSON or YAML formatted rules. If set, the entire chain of Kubernetes objects will be generated when credentials are requested. The value should be a `rules` key with an array of PolicyRule objects.
- `name_template` `(string: "")` – The name template to use when generating service accounts, roles and role bindings. If unset, a default template is used.
- `extra_annotations` `(map<string|string>: nil)` – Additional annotations to apply to all generated Kubernetes objects.
- `extra_labels` `(map<string|string>: nil)` – Additional labels to apply to all generated Kubernetes objects.


## Example Configurations

### Pre-existing Service Account

```hcl
test "kubernetes_secret" "k8s_sa_test" {
    weight = 100
    config {
        kubernetes {
            kubernetes_host = "https://kubernetes.example.com"
            service_account_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
            kubernetes_ca_cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
            disable_local_ca_jwt = true
            
        }
        role {
            name = "benchmark-sa-role"
            allowed_kubernetes_namespaces = ["default"]
            service_account_name = "vault-test"
            token_default_ttl = "1h"
            token_max_ttl = "24h"
        }
    }
}
```

### Pre-existing Role

```hcl
test "kubernetes_secret" "k8s_role_test" {
    weight = 100
    config {
        kubernetes {
            kubernetes_host = "https://kubernetes.example.com"
            service_account_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
            kubernetes_ca_cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
            disable_local_ca_jwt = true
        }
        role {
            name = "benchmark-role-binding"
            allowed_kubernetes_namespaces = ["development", "staging"]
            kubernetes_role_name = "vault-secrets-role"
            kubernetes_role_type = "ClusterRole"
            token_default_ttl = "30m"
            token_max_ttl = "4h"
        }
    }
}
```

### Generated Role Rules

```hcl
test "kubernetes_secret" "k8s_generated_test" {
    weight = 100
    config {
        kubernetes {
            kubernetes_host = "https://kubernetes.example.com"
            service_account_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
            kubernetes_ca_cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
            disable_local_ca_jwt = true
        }
        role {
            name = "benchmark-generated-role"
            allowed_kubernetes_namespaces = ["*"]
            kubernetes_role_type = "Role"
            generated_role_rules = <<EOT
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]
EOT
            token_default_ttl = "1h"
            token_max_ttl = "8h"
        }
    }
}
```

### Using Environment Variables

```hcl
test "kubernetes_secret" "k8s_env_test" {
    weight = 100
    config {
        kubernetes {
            kubernetes_host = "https://kubernetes.example.com"
        }
        role {
            name = "benchmark-env-role"
            allowed_kubernetes_namespaces = ["vault-system", "default"]
            service_account_name = "vault-benchmark"
            token_default_ttl = "1h"
            token_max_ttl = "24h"
            token_default_audiences = "https://kubernetes.default.svc.cluster.local"
        }
    }
}
```

### Advanced Configuration with Labels, Annotations and Environment Variables

```hcl
test "kubernetes_secret" "k8s_advanced_test" {
    weight = 100
    config {
        kubernetes {
            kubernetes_host = "https://kubernetes.example.com"
        }
        role {
            name = "benchmark-advanced-role"
            allowed_kubernetes_namespaces = ["production"]
            kubernetes_role_name = "app-access-role"
            kubernetes_role_type = "Role"
            token_default_ttl = "30m"
            token_max_ttl = "2h"
            name_template = "vault-{{.DisplayName}}-{{.RoleName}}-{{.Token.ID}}"
            extra_annotations = {
                "vault.io/managed-by" = "vault-benchmark"
                "app.kubernetes.io/created-by" = "vault"
            }
            extra_labels = {
                "vault.io/role" = "benchmark"
                "environment" = "production"
            }
        }
    }
}
```
