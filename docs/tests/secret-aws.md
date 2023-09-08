# AWS Secrets Engine Benchmark (`aws_secret`)

This benchmark will test the dynamic generation of AWS credentials.

## Test Parameters

### AWS Database Configuration `connection`

- `max_retries` `(int: -1)` - Number of max retries the client should use for
  recoverable errors. The default (`-1`) falls back to the AWS SDK's default
  behavior.
- `access_key` `(string: <required>)` – Specifies the AWS access key ID.  This can also be provided via the `VAULT_BENCHMARK_AWS_ACCESS_KEY` environment variable.
- `secret_key` `(string: <required>)` – Specifies the AWS secret access key.  This can also be provided via the `VAULT_BENCHMARK_AWS_SECRET_KEY` environment variable.
- `region` `(string: <optional>)` – Specifies the AWS region. If not set it
  will use the `AWS_REGION` env var, `AWS_DEFAULT_REGION` env var, or
  `us-east-1` in that order.
- `iam_endpoint` `(string: <optional>)` – Specifies a custom HTTP IAM endpoint to use.
- `sts_endpoint` `(string: <optional>)` – Specifies a custom HTTP STS endpoint to use.
- `username_template` `(string: <optional>)` - [Template](/vault/docs/concepts/username-templating) describing how
  dynamic usernames are generated. The username template is used to generate both IAM usernames (capped at 64 characters)
  and STS usernames (capped at 32 characters). Longer usernames result in a 500 error.

  To ensure generated usernames are within length limits for both STS/IAM, the template must adequately handle
  both conditional cases (see [Conditional Templates](https://pkg.go.dev/text/template)). As an example, if no template
  is provided the field defaults to the template below. It is to be noted that, DisplayName is the name of the vault
  authenticated user running the AWS credential generation and PolicyName is the name of the Role for which the
  credential is being generated for:

  ```
  {{ if (eq .Type "STS") }}
      {{ printf "vault-%s-%s" (unix_time) (random 20) | truncate 32 }}
  {{ else }}
      {{ printf "vault-%s-%s-%s" (printf "%s-%s" (.DisplayName) (.PolicyName) | truncate 42) (unix_time) (random 20) | truncate 64 }}
  {{ end }}
  ```

### Role Config `role`

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create. This
  is part of the request URL.
- `credential_type` `(string: "iam_user")` – Specifies the type of credential to be used when
  retrieving credentials from the role. Must be one of `iam_user`,
  `assumed_role`, or `federation_token`.
- `role_arns` `(list: [])` – Specifies the ARNs of the AWS roles this Vault role
  is allowed to assume. Required when `credential_type` is `assumed_role` and
  prohibited otherwise. This is a comma-separated string or JSON array.
- `policy_arns` `(list: [])` – Specifies a list of AWS managed policy ARN. The
  behavior depends on the credential type. With `iam_user`, the policies will
  be attached to IAM users when they are requested. With `assumed_role` and
  `federation_token`, the policy ARNs will act as a filter on what the
  credentials can do, similar to `policy_document`.
  When `credential_type` is `iam_user` or `federation_token`, at
  least one of `policy_arns` or `policy_document` must be specified. This is a
  comma-separated string or JSON array.
- `policy_document` `(string)` – The IAM policy document for the role. The
  behavior depends on the credential type. With `iam_user`, the policy document
  will be attached to the IAM user generated and augment the permissions the IAM
  user has. With `assumed_role` and `federation_token`, the policy document will
  act as a filter on what the credentials can do, similar to `policy_arns`.
- `iam_groups` `(list: [])` - A list of IAM group names. IAM users generated
  against this vault role will be added to these IAM Groups. For a credential
  type of `assumed_role` or `federation_token`, the policies sent to the
  corresponding AWS call (sts:AssumeRole or sts:GetFederation) will be the
  policies from each group in `iam_groups` combined with the `policy_document`
  and `policy_arns` parameters.
- `iam_tags` `(list: [])` - A list of strings representing a key/value pair to be used as a
  tag for any `iam_user` user that is created by this role. Format is a key and value
  separated by an `=` (e.g. `test_key=value`). Note: when using the CLI multiple tags
  can be specified in the role configuration by adding another `iam_tags` assignment
  in the same command.
- `default_sts_ttl` `(string)` - The default TTL for STS credentials. When a TTL is not
  specified when STS credentials are requested, and a default TTL is specified
  on the role, then this default TTL will be used. Valid only when
  `credential_type` is one of `assumed_role` or `federation_token`.
- `max_sts_ttl` `(string)` - The max allowed TTL for STS credentials (credentials
  TTL are capped to `max_sts_ttl`). Valid only when `credential_type` is one of
  `assumed_role` or `federation_token`.
- `user_path` `(string)` - The path for the user name. Valid only when
  `credential_type` is `iam_user`. Default is `/`
- `permissions_boundary_arn` `(string)` - The ARN of the [AWS Permissions
  Boundary](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
  to attach to IAM users created in the role. Valid only when `credential_type`
  is `iam_user`. If not specified, then no permissions boundary policy will be
  attached.

## Example Configuration

```hcl
test "aws_secret" "aws_test_1" {
    weight = 100
    config {
        connection {
            access_key = "$AWS_ACCESS_KEY"
            secret_key = "$AWS_SECRET_ACCESS_KEY"
        }
        role  {
            credential_type = "iam_user"
        }
    }
}
```

### Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-07-12T13:38:16.988-0400 [INFO]  vault-benchmark: setting up targets
2023-07-12T13:38:17.006-0400 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-07-12T13:38:22.015-0400 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op          count  rate       throughput  mean          95th%       99th%         successRatio
aws_test_1  31     10.364516  6.188835    1.288887342s  3.2954248s  3.666330125s  100.00%
```
