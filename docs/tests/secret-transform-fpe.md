# Transform FPE Configuration Options

This benchmark will test Vault's Transform secrets engine by performing Format Preserving Encryption (FPE) encoding on provided input.

## Test Parameters

### Role Config `role`

- `name` `(string: "benchmark-role")` –
  Specifies the name of the role to create. This is part of the request URL.

- `transformations` `(list: ["benchmarktransformation"])` -
  Specifies the transformations that can be used with this role.

### FPE Transformation Config `fpe`

- `name` `(string: "benchmarktransformation")` –
  Specifies the name of the FPE transformation to create or update. This is part
  of the request URL.

- `template` `(string: "builtin/creditcardnumber")` -
  The name of a single template to use for matching. Mutually exclusive with
  `templates`. Built-in options include `builtin/creditcardnumber`,
  `builtin/socialsecuritynumber`, and any custom template you have created.

- `templates` `(list: [])` -
  A list of template names to use for matching. Mutually exclusive with
  `template`. When provided, the first matching template is used.

- `tweak_source` `(string: "supplied")` -
  Specifies the source of where the tweak value comes from. Valid values are:
  - `supplied` – the tweak must be provided with each encode/decode request
  - `generated` – a tweak is generated and returned with each encode operation
  - `internal` – a tweak is generated and stored internally; no tweak is
    returned or required

- `allowed_roles` `(list: ["benchmark-role"])` -
  Specifies a list of allowed roles that this transformation can be assigned to.
  A role using this transformation must exist in this list in order for encode
  and decode operations to properly function.

- `max_tweak_len` `(int: 0)` -
  The maximum tweak size allowed for this transformation.
  This field cannot be updated. If the value is `0`, the tweak can be of any length.


### Alphabet Config `alphabet` *(optional)*

Omit this block to use the built-in `builtin/numeric` alphabet. Provide it only
when a custom character set is required.

- `name` `(string: <required>)` –
  The name under which the custom alphabet will be stored. This value must match
  any reference to the alphabet in a custom template.

- `alphabet` `(string: <required>)` –
  A string of characters that defines the valid characters for FPE encoding.
  Each character must be unique. The length must be between 2 and 65536.

### Encode Input `input`

- `value` `(string: "1111-1111-1111-1111")` –
  Specifies the value to be encoded. Must match the format defined by the
  transformation's template.

- `transformation` `(string: "benchmarktransformation")` –
  Specifies the transformation within the role that should be used for this
  encode operation. If a single transformation exists for the role, this
  parameter may be skipped and will be inferred. If multiple transformations
  exist, one must be specified.

- `tweak` `(string: "")` –
  Specifies the **base64 encoded** tweak to use. Only applicable for FPE
  transformations with `supplied` as the tweak source. The tweak must be a
  7-byte value that is then base64 encoded.

- `reference` `(string: "")` -
  A user-supplied string that will be present in the `reference` field on the
  corresponding `batch_results` item in the response, to assist in understanding
  which result corresponds to a particular input. Only valid on batch requests
  when using `batch_input` below.

- `batch_input` `(array<object>: nil)` -
  Specifies a list of items to be encoded in a single batch. When this parameter
  is set, the `value`, `transformation`, `tweak`, and `reference` parameters are
  ignored. Instead, the aforementioned parameters should be provided within each
  object in the list.

  ```json
  [
    {
      "value": "1111-1111-1111-1111",
      "transformation": "ccn-fpe"
    },
    {
      "value": "2222-2222-2222-2222",
      "transformation": "ccn-fpe",
      "reference": "order#1234"
    }
  ]
  ```

## Example HCL Configurations

### Minimal — internal tweak, built-in credit card template

```hcl
test "transform_fpe" "fpe_test1" {
  weight = 100
  config {
    fpe {
      tweak_source = "internal"
    }
    input {
      value = "1111-1111-1111-1111"
    }
  }
}
```

### Supplied tweak

```hcl
test "transform_fpe" "fpe_test_supplied_tweak" {
  weight = 100
  config {
    role {
      name            = "benchmark-role"
      transformations = ["ccn-fpe"]
    }
    fpe {
      name          = "ccn-fpe"
      template      = "builtin/creditcardnumber"
      tweak_source  = "supplied"
      allowed_roles = ["benchmark-role"]
    }
    input {
      transformation = "ccn-fpe"
      value          = "1111-1111-1111-1111"
      # base64 encoding of a 7-byte tweak value
      tweak          = "dGVzdHR3ZQ=="
    }
  }
}
```

### Custom alphabet

```hcl
test "transform_fpe" "fpe_test_custom_alphabet" {
  weight = 100
  config {
    alphabet {
      name     = "hex"
      alphabet = "0123456789abcdef"
    }
    role {
      name            = "benchmark-role"
      transformations = ["hex-fpe"]
    }
    fpe {
      name          = "hex-fpe"
      template      = "builtin/creditcardnumber"
      tweak_source  = "internal"
      allowed_roles = ["benchmark-role"]
    }
    input {
      transformation = "hex-fpe"
      value          = "1111-1111-1111-1111"
    }
  }
}
```
