# RADIUS Authentication Method

The RADIUS authentication method allows users to authenticate with Vault using an existing RADIUS server that accepts the PAP (Password Authentication Protocol) authentication scheme.

## Test Parameters

### RADIUS Auth Configuration (`auth`)

| Name | Description | Required | Default | Type |
| ---- | ----------- | -------- | ------- | ---- |
| `host` | The RADIUS server to connect to | **Yes** | `127.0.0.1` | `string` |
| `port` | The UDP port where the RADIUS server is listening | No | `1812` | `int` |
| `secret` | The RADIUS shared secret | **Yes** | | `string` |
| `unregistered_user_policies` | Comma-separated list of policies for unregistered users | No | | `[]string` |
| `dial_timeout` | Number of seconds to wait for a backend connection | No | `10` | `int` |
| `nas_port` | The NAS-Port attribute of the RADIUS request | No | `10` | `int` |
| `token_ttl` | The incremental lifetime for generated tokens | No | | `string` |
| `token_max_ttl` | The maximum lifetime for generated tokens | No | | `string` |
| `token_policies` | List of token policies to encode onto generated tokens | No | | `[]string` |
| `token_bound_cidrs` | List of CIDR blocks for IP address restrictions | No | | `[]string` |
| `token_explicit_max_ttl` | Explicit max TTL for tokens | No | | `string` |
| `token_no_default_policy` | If true, default policy will not be set | No | `false` | `bool` |
| `token_num_uses` | Maximum number of times a token may be used | No | `0` | `int` |
| `token_period` | The maximum allowed period value for periodic tokens | No | | `string` |
| `token_type` | The type of token that should be generated | No | | `string` |

### RADIUS Test User Configuration (`test_user`)

| Name | Description | Required | Default | Type |
| ---- | ----------- | -------- | ------- | ---- |
| `username` | Username for the test user | **Yes** | `testuser` | `string` |
| `password` | Password for the test user | **Yes** | `testpass123` | `string` |
| `policies` | List of policies to assign to the user | No | `["default"]` | `[]string` |

## Environment Variables

| Name | Description | Required |
| ---- | ----------- | -------- |
| `VAULT_BENCHMARK_RADIUS_TEST_USERNAME` | Username for RADIUS authentication testing | No |
| `VAULT_BENCHMARK_RADIUS_TEST_PASSWORD` | Password for RADIUS authentication testing | No |
| `VAULT_BENCHMARK_RADIUS_SECRET` | RADIUS shared secret | No |

## RADIUS Server Requirements

For this benchmark to work properly, you need a RADIUS server configured with:

1. **PAP Authentication**: The server must support Password Authentication Protocol
2. **Shared Secret**: Must match the secret configured in Vault
3. **User Accounts**: Test users must be configured on the RADIUS server
4. **Network Access**: The RADIUS server must be accessible from where vault-benchmark runs

## Sample Test Configuration

```hcl
test "radius_auth" "radius_basic" {
    weight = 100
    config {
        auth {
            host = "127.0.0.1"
            port = 1812
            secret = "vault123"
            dial_timeout = 10
            token_ttl = "1h"
            token_max_ttl = "8h"
        }

        test_user {
            username = "testuser"
            password = "testpass123"
            policies = ["default"]
        }
    }
}
```

## Important Notes

1. **RADIUS Server Dependency**: This benchmark requires a functioning RADIUS server
2. **Network Connectivity**: Ensure the RADIUS server is accessible from the benchmark environment
3. **Authentication Protocol**: Only PAP (Password Authentication Protocol) is supported
4. **Security**: Use strong shared secrets in production environments
5. **User Management**: Test users must exist on the RADIUS server
6. **Firewall**: Ensure UDP port 1812 (auth) and 1813 (accounting) are open if needed

## Troubleshooting

### Common Issues

1. **Connection Timeout**
   - Verify RADIUS server is running
   - Check network connectivity to RADIUS server
   - Verify firewall settings allow UDP traffic on port 1812

2. **Authentication Failures**
   - Verify user exists on RADIUS server
   - Check username/password combination
   - Verify shared secret matches between Vault and RADIUS server

3. **Configuration Errors**
   - Ensure required parameters (host, secret, username, password) are provided
   - Check HCL syntax in configuration files

### Debug Commands

```bash
# Test RADIUS server connectivity
nc -u 127.0.0.1 1812

# Test RADIUS authentication directly
radtest username password radius_host 1812 shared_secret

# Check Vault RADIUS configuration
vault auth list
vault read auth/radius/config

# Enable Vault debug logging
export VAULT_LOG_LEVEL=debug
```

## Performance Considerations

1. **Connection Pooling**: RADIUS connections are created per request
2. **Timeout Settings**: Adjust `dial_timeout` based on network latency
3. **Server Load**: Monitor RADIUS server performance under load
4. **Rate Limiting**: Consider RADIUS server rate limiting capabilities

## Example Usage
```bash
./vault-benchmark run -config=test-radius.hcl
2025-08-30T19:39:11.634+0530 [INFO]  vault-benchmark: setting up targets
2025-08-30T19:39:13.655+0530 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2025-08-30T19:39:23.658+0530 [INFO]  vault-benchmark: cleaning up targets
2025-08-30T19:39:26.887+0530 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op           count  rate         throughput   mean        95th%       99th%       successRatio
radius_test  31143  3114.303685  3113.668639  3.206479ms  7.682566ms  9.522433ms  100.00%
```
