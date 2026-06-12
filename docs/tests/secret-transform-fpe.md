# Transform FPE (Format Preserving Encryption) Configuration Options

This benchmark will test Vault's Transform secrets engine by performing Format Preserving Encryption (FPE) encoding on provided input using the FF3-1 algorithm.

## Test Parameters

### Role Config `role`

- `name` `(string: "benchmark-role")` –
  Specifies the name of the role to create. This is part of the request URL.

- `transformations` (`list: ["benchmarkfpetransformation"]`) -
  Specifies the transformations that can be used with this role.

### FPE Config `fpe`

- `name` `(string: "benchmarkfpetransformation")` –
  Specifies the name of the FPE transformation to create or update. This is part
  of the request URL.

- `template` `(string: "benchmarkfpetemplate")` –
  Specifies the template to use for FPE encoding. The template defines the
  format and alphabet of the data to be encrypted.

- `tweak_source` `(string: "internal")` –
  Specifies the source of the tweak value. Options are `internal`, `generated`,
  and `supplied`. When set to `internal`, Vault generates and stores the tweak
  internally. When set to `generated`, Vault generates a tweak and returns it
  with the response. When set to `supplied`, the caller must provide a tweak
  value with every encode request.

- `allowed_roles` `(list: ["benchmark-role"])` –
  Specifies a list of allowed roles that this transformation can be assigned to.
  A role using this transformation must exist in this list in order for
  encode and decode operations to properly function.

### Encode Input `input`

- `role_name` `(string: "benchmark-role")` –
  Specifies the role name to use for this operation. This is specified as part
  of the URL.

- `value` `(string: "1111-2222-3333-4444")` –
  Specifies the value to be encoded. Must match the format defined in the
  transformation template.

- `transformation` `(string: "benchmarkfpetransformation")` –
  Specifies the transformation within the role that should be used for this
  encode operation. If a single transformation exists for role, this parameter
  may be skipped and will be inferred. If multiple transformations exist, one
  must be specified.

- `tweak` `(string)` –
  Specifies the **base64 encoded** tweak to use. Only applicable for FPE
  transformations with `supplied` as the tweak source. The tweak must be a
  7-byte value that is then base64 encoded.

- `reference` `(string: "")` -
  A user-supplied string that will be present in the `reference` field on the
  corresponding `batch_results` item in the response, to assist in understanding
  which result corresponds to a particular input. Only valid on batch requests
  when using 'batch_input' below.

- `batch_input` `(array<object>: nil)` -
  Specifies a list of items to be encoded in a single batch. When this
  parameter is set, the 'value', 'transformation', 'tweak' and
  'reference' parameters are ignored. Instead, the aforementioned parameters
  should be provided within each object in the list.
```json
  [
    {
      "value": "1111-2222-3333-4444",
      "transformation": "benchmarkfpetransformation"
    },
    {
      "value": "5555-6666-7777-8888",
      "transformation": "benchmarkfpetransformation",
      "tweak": "H0mSPAfSJg=="
    }
  ]
```

### Example Configuration
```hcl
test "transform_fpe" "fpe_test" {
  weight = 100
  config {
    role {
      name            = "benchmark-role"
      transformations = ["benchmarkfpetransformation"]
    }
    fpe {
      name          = "benchmarkfpetransformation"
      template      = "benchmarkfpetemplate"
      tweak_source  = "internal"
      allowed_roles = ["benchmark-role"]
    }
    input {
      value          = "1111-2222-3333-4444"
      transformation = "benchmarkfpetransformation"
    }
  }
}
```