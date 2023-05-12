#!/bin/sh

echo "Unsealing vault..."
export VAULT_ADDR="http://vault:8200"
primaryInitRaw=$(vault operator init -format=json -n 1 -t 1)
primaryUnseal=$(echo ${primaryInitRaw?} | jq -r '.unseal_keys_b64[0]')
primaryRootToken=$(echo ${primaryInitRaw?} | jq -r '.root_token')
vault operator unseal ${primaryUnseal?}
echo "===================================="
echo ${primaryRootToken} > /etc/output.txt
echo "Root Token: " $primaryRootToken
echo "===================================="
