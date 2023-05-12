# To run tests
```sh
docker compose up

# wait enough time for cassandra database to get setup (it takes a bit to settle)
# then run vault-benchmark with configs/test_configs.hcl
vault-benchmark run -config=configs/test_configs.hcl
vault-benchmark run -config=./docker_tests/configs/test_configs.hcl 
```