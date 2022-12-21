# Kubernetes Auth Configuration Options

This benchmark will test Vault authentication using the Kubernetes Auth method. In order to use this test, configuration for the target Kubernetes cluster must be provided as a JSON file using the `k8s_config_json` flag. The primary required field is `kubernetes_host`. A role config also needs to be passed with the primary required fields being `name`, `bound_service_account_names`, and `bound_service_account_namespaces`. Included is an example `benchmark-vault-job.yaml` file which can be applied to use the benchmark-vault image in a Kubernetes cluster. This example assumes a Vault cluster deployed in a Kubernetes environment based on our [Vault Installation to Minikube via Helm with Integrated Storage](https://learn.hashicorp.com/tutorials/vault/kubernetes-minikube-raft?in=vault/kubernetes) learn guide. This file can be edited to suit a specific deployment methodology. Below is the ConfigMap snippet showing example configuration:

## Test Parameters (minimum 1 required)

- `pct_k8s_login`: percent of requests that are Kubernetes logins

## Additional Parameters

- `k8s_config_json` _(required)_: path to JSON file containing Vault K8s configuration.  Configuration options can be found in the [Kubernetes Vault documentation](https://developer.hashicorp.com/vault/api-docs/auth/kubernetes#configure-method).
- `k8s_role_config_json` _(required)_: path to JSON file containing test user credentials.

### Example benchmark-vault-job.yaml

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: benchmark-vault-configmap
data:
  k8s_config.json: |
    {
      "kubernetes_host":"https://kubernetes.default.svc"
    }
  k8s_role_config.json: |
    {
      "name":"benchmark-vault-role",
      "bound_service_account_names":["benchmark-vault"],
      "bound_service_account_namespaces":["*"],
      "token_max_ttl":"24h",
      "token_ttl":"1h"
    }
```

## Example Usage

```bash
$ benchmark-vault -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_k8s_login=100 \
    -k8s_config_json=/path/to/k8s/config.json \
    -k8s_test_user_creds_json=/path/to/k8s/test_user_creds.json
op          count  rate        throughput  mean         95th%         99th%        successRatio
Kubernetes login  1581   157.678405  156.778405    63.310542ms  193.090504ms  199.27467ms  100.00%
```

Please refer to the [Vault Kubernetes Auth Method](https://www.vaultproject.io/api-docs/auth/kubernetes) documentation for all available configuration options.
