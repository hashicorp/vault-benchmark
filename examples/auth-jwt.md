# JWT (JSON Web Token) Auth Configuration Options

This benchmark tests the performance of logins using the jwt auth method.

## Test Parameters

### Role Config

- `name` _(string: "benchmark-role")_: Specifies the name of the role to create.
- `role_type` _(string: "jwt")_: Type of role, either "oidc" or "jwt".
- `bound_audiences` _(string: "https://vault.plugin.auth.jwt.test")_: List of aud claims to match against. Any match is sufficient. For "jwt" roles, at least one of bound_audiences, bound_subject, bound_claims or token_bound_cidrs is required. Optional for "oidc" roles.
- `user_claim` _(string: "https://vault/user")_: The claim to use to uniquely identify the user; this will be used as the name for the Identity entity alias created due to a successful login. The claim value must be a string.

## Example Configuration

```hcl
test "jwt_auth" "jwt_test_1" {
    weight = 100
}
```

### Example Usage

```bash
$ vault-benchmark run -config=example-configs/jwt/config.hcl
Setting up targets...
Starting benchmarks. Will run for 2s...
Benchmark complete!
Target: http://127.0.0.1:8200
op          count  rate         throughput   mean        95th%       99th%       successRatio
jwt_test_1  15490  7744.671498  7740.769669  1.288231ms  2.570901ms  4.245567ms  100.00%
```
