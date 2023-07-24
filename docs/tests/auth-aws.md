# AWS Authentication Credential Benchmark (`aws_auth`)

This benchmark tests the performance of logins using the AWS auth method.

## Benchmark Configuration Parameters

### AWS Authentication Configuration (`auth`)`

- `max_retries` `(int: -1)` - Number of max retries the client should use for recoverable errors. The default (`-1`) falls back to the AWS SDK's default behavior.
- `access_key` `(string: "")` - AWS Access key with permissions to query AWS APIs. The permissions required depend on the specific configurations. If using the `iam` auth method without inferencing, then no credentials are necessary. If using the `ec2` auth method or using the `iam` auth method with inferencing, then these credentials need access to `ec2:DescribeInstances`. If additionally a `bound_iam_role` is specified, then these credentials also need access to `iam:GetInstanceProfile`. If, however, an alternate sts configuration is set for the target account, then the credentials must be permissioned to call `sts:AssumeRole` on the configured role, and that role must have the permissions described here.  This can also be provided via the `VAULT_BENCHMARK_AWS_ACCESS_KEY` environment variable.
- `secret_key` `(string: "")` - AWS Secret key with permissions to query AWS APIs.  This can also be provided via the `VAULT_BENCHMARK_AWS_SECRET_KEY` environment variable.
- `endpoint` `(string: "")` - URL to override the default generated endpoint for making AWS EC2 API calls.
- `iam_endpoint` `(string: "")` - URL to override the default generated endpoint for making AWS IAM API calls.
- `sts_endpoint` `(string: "")` - URL to override the default generated endpoint for making AWS STS API calls. If set, `sts_region` should also be set.
- `sts_region` `(string: "")` - Region to override the default region for making AWS STS API calls. Should only be set if `sts_endpoint` is set. If so, should be set to the region in which the custom `sts_endpoint` resides.
- `iam_server_id_header_value` `(string: "")` - The value to require in the `X-Vault-AWS-IAM-Server-ID` header as part of GetCallerIdentity requests that are used in the iam auth method. If not set, then no value is required or validated. If set, clients must include an X-Vault-AWS-IAM-Server-ID header in the headers of login requests, and further this header must be among the signed headers validated by AWS. This is to protect against different types of replay attacks, for example a signed request sent to a dev server being resent to a production server. Consider setting this to the Vault server's DNS name.
- `allowed_sts_header_values` `(string: "")` A comma separated list of additional request headers permitted when providing the iam_request_headers for an IAM based login call. In any case, a default list of headers AWS STS expects for a GetCallerIdentity are allowed.

### AWS Role Configuration (`test_user`)`

- `role` `(string: <required>)` - Name of the role. Vault normalizes all role names to lower case. If you create two roles, "Web-Workers" and "WEB-WORKERS", they will both be normalized to "web-workers" and will be regarded as the same role. This is to prevent unexpected behavior due to casing differences. At all points, Vault can be provided the role in any casing, and it will internally handle sending it to lower case and seeking it inside its storage engine.
- `auth_type` `(string: "iam")` - The auth type permitted for this role. Valid choices are "ec2" or "iam". If no value is specified, then it will default to "iam" (except for legacy `aws-ec2` auth types, for which it will default to "ec2"). Only those bindings applicable to the auth type chosen will be allowed to be configured on the role.
- `bound_ami_id` `(list: [])` - If set, defines a constraint on the EC2 instances that they should be using one of the AMI ID specified by this parameter. This constraint is checked during ec2 auth as well as the iam auth method only when inferring an EC2 instance. This is a comma-separated string or JSON array.
- `bound_account_id` `(list: [])` - If set, defines a constraint on the EC2 instances that the account ID in its identity document to match one of the ones specified by this parameter. This constraint is checked during ec2 auth as well as the iam auth method only when inferring an EC2 instance. This is a comma-separated string or JSON array.
- `bound_region` `(list: [])` - If set, defines a constraint on the EC2 instances that the region in its identity document must match one of the regions specified by this parameter. This constraint is only checked by the ec2 auth method as well as the iam auth method only when inferring an ec2 instance. This is a comma-separated string or JSON array.
- `bound_vpc_id` `(list: [])` - If set, defines a constraint on the EC2 instance to be associated with a VPC ID that matches one of the values specified by this parameter. This constraint is only checked by the ec2 auth method as well as the iam auth method only when inferring an ec2 instance. This is a comma-separated string or JSON array.
- `bound_subnet_id` `(list: [])` - If set, defines a constraint on the EC2 instance to be associated with a subnet ID that matches one of the values specified by this parameter. This constraint is only checked by the ec2 auth method as well as the iam auth method only when inferring an ec2 instance. This is a comma-separated string or a JSON array.
- `bound_iam_role_arn` `(list: [])` - If set, defines a constraint on the authenticating EC2 instance that it must match one of the IAM role ARNs specified by this parameter. Wildcards are supported at the end of the ARN to allow for prefix matching. The configured IAM user or EC2 instance role must be allowed to execute the `iam:GetInstanceProfile` action if this is specified. This constraint is checked by the ec2 auth method as well as the iam auth method only when inferring an EC2 instance. This is a comma-separated string or a JSON array.
- `bound_iam_instance_profile_arn` `(list: [])` - If set, defines a constraint on the EC2 instances to be associated with an IAM instance profile ARN. Wildcards are supported at the end of the ARN to allow for prefix matching. This constraint is checked by the ec2 auth method as well as the iam auth method only when inferring an ec2 instance. This is a comma-separated string or a JSON array.
- `bound_ec2_instance_id` `(list: [])` - If set, defines a constraint on the EC2 instances to have one of these instance IDs. This constraint is checked by the ec2 auth method as well as the iam auth method only when inferring an ec2 instance. This is a comma-separated string or a JSON array.
- `role_tag` `(string: "")` - If set, enables the role tags for this role. The value set for this field should be the 'key' of the tag on the EC2 instance. The 'value' of the tag should be generated using `role/<role>/tag` endpoint. Defaults to an empty string, meaning that role tags are disabled. This constraint is valid only with the ec2 auth method and is not allowed when `auth_type` is iam.
- `bound_iam_principal_arn` `(list: [])` - Defines the list of IAM principals that are permitted to login to the role using the iam auth method. Individual values should look like "arn:aws:iam::123456789012:user/MyUserName" or "arn:aws:iam::123456789012:role/MyRoleName". Wildcards are supported at the end of the ARN, e.g., "arn:aws:iam::123456789012:\*" will match any IAM principal in the AWS account 123456789012. When `resolve_aws_unique_ids` is `false` and you are binding to IAM roles (as opposed to users) and you are not using a wildcard at the end, then you must specify the ARN by omitting any path component; see the documentation for `resolve_aws_unique_ids` below. This constraint is only checked by the iam auth method. Wildcards are supported at the end of the ARN, e.g., "arn:aws:iam::123456789012:role/\*" will match all roles in the AWS account. This is a comma-separated string or JSON array.
- `inferred_entity_type` `(string: "")` - When set, instructs Vault to turn on inferencing. The only current valid value is "ec2_instance" instructing Vault to infer that the role comes from an EC2 instance in an IAM instance profile. This only applies to the iam auth method. If you set this on an existing role where it had not previously been set, tokens that had been created prior will not be renewable; clients will need to get a new token.
- `inferred_aws_region` `(string: "")` - When role inferencing is activated, the region to search for the inferred entities (e.g., EC2 instances). Required if role inferencing is activated. This only applies to the iam auth method.
- `resolve_aws_unique_ids` `(bool: true)` - When set, resolves the `bound_iam_principal_arn` to the [AWS Unique ID](http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers#identifiers-unique-ids) for the bound principal ARN. This field is ignored when `bound_iam_principal_arn` ends with a wildcard character. This requires Vault to be able to call `iam:GetUser` or `iam:GetRole` on the `bound_iam_principal_arn` that is being bound. Resolving to internal AWS IDs more closely mimics the behavior of AWS services in that if an IAM user or role is deleted and a new one is recreated with the same name, those new users or roles won't get access to roles in Vault that were permissioned to the prior principals of the same name. The default value for new roles is true, while the default value for roles that existed prior to this option existing is false (you can check the value for a given role using the GET method on the role). Any authentication tokens created prior to this being supported won't verify the unique ID upon token renewal. When this is changed from false to true on an existing role, Vault will attempt to resolve the role's bound IAM ARN to the unique ID and, if unable to do so, will fail to enable this option. Changing this from `true` to `false` is not supported; if absolutely necessary, you would need to delete the role and recreate it explicitly setting it to `false`. However; the instances in which you would want to do this should be rare. If the role creation (or upgrading to use this) succeed, then Vault has already been able to resolve internal IDs, and it doesn't need any further IAM permissions to authenticate users. If a role has been deleted and recreated, and Vault has cached the old unique ID, you should just call this endpoint specifying the same `bound_iam_principal_arn` and, as long as Vault still has the necessary IAM permissions to resolve the unique ID, Vault will update the unique ID. (If it does not have the necessary permissions to resolve the unique ID, then it will fail to update.) If this option is set to false, then you MUST leave out the path component in `bound_iam_principal_arn` for **roles** that do not specify a wildcard at the end, but not IAM users or role bindings that have a wildcard. That is, if your IAM role ARN is of the form `arn:aws:iam::123456789012:role/some/path/to/MyRoleName`, and `resolve_aws_unique_ids` is `false`, you **must** specify a `bound_iam_principal_arn` of `arn:aws:iam::123456789012:role/MyRoleName` for authentication to work. - `allow_instance_migration` `(bool: false)` - If set, allows migration of the underlying instance where the client resides. This keys off of pendingTime in the metadata document, so essentially, this disables the client nonce check whenever the instance is migrated to a new host and pendingTime is newer than the previously-remembered time. Use with caution. This only applies to authentications via the ec2 auth method. This is mutually exclusive with `disallow_reauthentication`.
- `disallow_reauthentication` `(bool: false)` - If set, only allows a single token to be granted per instance ID. In order to perform a fresh login, the entry in the access list for the instance ID needs to be cleared using `auth/aws/identity-accesslist/<instance_id>` endpoint. Defaults to 'false'. This only applies to authentications via the ec2 auth method. This is mutually exclusive with `allow_instance_migration`.

## Example HCL

```hcl
test "aws_auth" "aws_test_1" {
    weight = 100
    config {
        auth {
            access_key = "$AWS_ACCESS_KEY"
            secret_key = "$AWS_SECRET_ACCESS_KEY"
            iam_server_id_header_value = "vault.example.com"
        }
        test_user  {
            bound_iam_principal_arn = "arn:aws:iam::1234567891011:*"
            auth_type = "iam"
            role = "dev-role-iam"
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-04-26T17:52:03.294-0500 [INFO]  vault-benchmark: setting up targets
2023-04-26T17:52:03.320-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-26T17:52:05.322-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op          count  rate      throughput  mean         95th%         99th%         successRatio
aws_test_1  13     6.231426  3.808569    1.89813632s  2.160728904s  2.160794417s  100.00%
```
