#!/usr/bin/env bash
# NOTE: Before running this script, temporarily raise identityConcurrency in
# benchmarktests/concurrency_helper.go from 1 to ~16.  The SCIM benchmarks seed
# large numbers of identity entities and groups, and the higher concurrency cuts
# setup time significantly.  Restore the value to 1 before committing.
set -e

echo "=== [1/8] Running User Creation Spike ==="
go run main.go run -config=test-fixtures/configs/scim/scim_user_create_spike.hcl > results_user_create_spike.log 2>&1

echo "=== [2/8] Running User Adoption Spike ==="
go run main.go run -config=test-fixtures/configs/scim/scim_user_adopt_spike.hcl > results_user_adopt_spike.log 2>&1

echo "=== [3/8] Running User Scale Limit (12k users) ==="
go run main.go run -config=test-fixtures/configs/scim/scim_user_scale_limit.hcl > results_user_scale_limit.log 2>&1

echo "=== [4/8] Running User Filter Performance ==="
go run main.go run -config=test-fixtures/configs/scim/scim_user_filter_perf.hcl > results_user_filter_perf.log 2>&1

echo "=== [5/8] Running Group Creation Spike ==="
go run main.go run -config=test-fixtures/configs/scim/scim_group_create_spike.hcl > results_group_create_spike.log 2>&1

echo "=== [6/8] Running Group Adoption Spike ==="
go run main.go run -config=test-fixtures/configs/scim/scim_group_adopt_spike.hcl > results_group_adopt_spike.log 2>&1

echo "=== [7/8] Running Group Membership Stress ==="
go run main.go run -config=test-fixtures/configs/scim/scim_group_membership_stress.hcl > results_group_membership_stress.log 2>&1

echo "=== [8/8] Running Group Filter Performance ==="
go run main.go run -config=test-fixtures/configs/scim/scim_group_filter_perf.hcl > results_group_filter_perf.log 2>&1

echo "=== All 8 SCIM Benchmark Tests Complete! ==="
