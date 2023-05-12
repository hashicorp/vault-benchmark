#!/bin/sh

# install jq
# echo "Installing jq..."
# apk add wget

# wget https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 && \
#     mv jq-linux64 /usr/local/bin/jq && \
#     chmod +x /usr/local/bin/jq

# unsealing vault
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
