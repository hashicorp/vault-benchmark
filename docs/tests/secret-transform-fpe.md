# Transform FPE Configuration Options

This benchmark will test Vault's Transform secrets engine by performing Format
Preserving Encryption (FPE) encoding on credit card numbers.

## Test Parameters

### Role Config `role`

- `name` `(string: "benchmark-role")` –
  Specifies the name of the role to create. This is part of the request URL.

- `transformations` (`list: ["benchmarktransformation"]`) -
  Specifies the transformations that can be used with this role.

### FPE Config `fpe`

- `name` `(string: "benchmarktransformation")` –
  Specifies the name of the transformation to create or update. This is part of
  the request URL.

- `template` `(string: "builtin/creditcardnumber")` -
  Specifies the template to use for Format Preserving Encryption. This test
  uses the built-in credit card number template.

- `tweak_source` `(string: "internal")` -
  Specifies the source of the tweak value. `internal` means Vault will generate
  and manage the tweak internally.

- `allowed_roles` `(list: ["benchmark-role"])` -
  Specifies a list of allowed roles that this transformation can be assigned to.
  A role using this transformation must exist in this list in order for
  encode operations to properly function.

### Encode Input `input`

- `value` `(string: "4111-1111-1111-1111")` –
  Specifies the credit card number to be encoded. Must match the credit card
  number format expected by the builtin/creditcardnumber template.

- `data_mode` `(string: "static")` –
  Specifies how input data is generated for batch operations. Valid values are:
  - `static`: All batch items use the same `value` (default)
  - `sequential`: Generate sequential credit card numbers by incrementing the
    last 4 digits

- `transformation` `(string: "benchmarktransformation")` –
  Specifies the transformation within the role that should be used for this
  encode operation. If a single transformation exists for role, this parameter
  may be skipped and will be inferred.

- `batch_size` `(int: 0)` -
  If greater than 0, generates a batch request with this many items. The content
  of each batch item depends on the `data_mode` setting:
  - `static`: All items use the same `value`
  - `sequential`: Each item uses an incremented credit card number

- `batch_input` `(array<object>: nil)` -
  Specifies a list of items to be encoded in a single batch. When this
  parameter is set, the 'value', 'transformation', and 'batch_size' parameters
  are ignored. Instead, provide objects with 'value' and 'transformation' fields.

  ```json
  [
    {
      "value": "4111-1111-1111-1111",
      "transformation": "benchmarktransformation"
    },
    {
      "value": "5555-5555-5555-4444",
      "transformation": "benchmarktransformation"
    }
  ]
  ```

## Example Configurations

### Single Credit Card Number

```hcl
test "transform_fpe" "single_cc" {
  weight = 100
  config {
    input {
      value = "4111-1111-1111-1111"
    }
  }
}
```

### Batch Processing - 10 Items per Request (Static)

```hcl
test "transform_fpe" "batch_10_static" {
  weight = 100
  config {
    input {
      value = "4111-1111-1111-1111"
      data_mode = "static"
      batch_size = 10
    }
  }
}
```

### Sequential Batch Processing - 5 Items with Different Numbers

```hcl
test "transform_fpe" "batch_5_sequential" {
  weight = 100
  config {
    input {
      value = "4111-1111-1111-1111"
      data_mode = "sequential"
      batch_size = 5
    }
  }
}
```

This will generate:

- 4111-1111-1111-1111
- 4111-1111-1111-1112
- 4111-1111-1111-1113
- 4111-1111-1111-1114
- 4111-1111-1111-1115

### Custom Batch Input

```hcl
test "transform_fpe" "custom_batch" {
  weight = 100
  config {
    input {
      batch_input = [
        {
          value = "4111-1111-1111-1111"
          transformation = "benchmarktransformation"
        },
        {
          value = "5555-5555-5555-4444"
          transformation = "benchmarktransformation"
        }
      ]
    }
  }
}
```

## Performance Testing Usage

Users can test different batch sizes by creating separate configuration files:

```bash
# Test single operations
vault-benchmark run -config=fpe-single.hcl

# Test small batches
vault-benchmark run -config=fpe-batch-5.hcl

# Test large batches
vault-benchmark run -config=fpe-batch-100.hcl
```

Each configuration can specify different `batch_size` values to determine optimal
throughput for FPE operations in your environment.