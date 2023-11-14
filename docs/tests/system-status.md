# System Status Configuration Options

## Example Configuration

```hcl
test "ha_status" "ha_status_test_1" {
    weight = 30
}

test "seal_status" "seal_status_test_1" {
    weight = 30
}

test "metrics" "metrics_test_1" {
    weight = 40
}
```
