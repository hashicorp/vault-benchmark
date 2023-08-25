#!/bin/bash

# Output file name
output_file="docs/index.md"

# Function to extract the title from a Markdown file
extract_title() {
    title=$(grep -E "^# (.*)" "$1" | sed -E "s/^# (.*)/\1/")
    echo "$title"
}

# Function to generate the list of benchmark tests
generate_tests_list() {
    auth_tests_list=""
    secret_tests_list=""
    system_tests_list=""
    for test_file in $(ls -1 docs/tests/* | sort); do
        if [[ -f "$test_file" ]]; then
            test_name=$(basename "$test_file")
            test_link="[$(extract_title "$test_file")]($test_file)"
            if [[ "$test_name" == *"auth"* ]]; then
                auth_tests_list+="\n- $test_link"
            elif [[ "$test_name" == *"secret"* ]]; then
                secret_tests_list+="\n- $test_link"
            elif [[ "$test_name" == *"system"* ]]; then
                system_tests_list+="\n- $test_link"
            fi
        fi
    done
    echo "\n\n### Auth Benchmark Tests$auth_tests_list\n\n### Secret Benchmark Tests$secret_tests_list\n\n### System Tests$system_tests_list"
}

# Create the Markdown content
markdown_content="# Vault Benchmark
\`vault-benchmark\` has two subcommands, \`run\` and \`review\`. The \`run\` command is the main command used to execute a benchmark run using the provided benchmark test configuration. Configuration is provided as an HCL formatted file containing the desired global configuration options for \`vault-benchmark\` itself as well as the test definitions and their respective configuration options.

## Example Config
\`\`\`hcl
# Global vault-benchmark config options
vault_addr = \"http://127.0.0.1:8200\"
vault_token = \"root\"
vault_namespace=\"root\"
duration = \"2s\"
report_mode = \"terse\"
random_mounts = true
cleanup = true

# Test definitions and configuration
test \"approle_auth\" \"approle_auth_test1\" {
    weight = 100
    config {
        role {
            role_name = \"benchmark-role\"
            token_ttl=\"2m\"
        }
    }
}
\`\`\`

## Subcommands
- [Run](commands/run.md)
- [Review](commands/review.md)

## Benchmark Tests$(generate_tests_list)

## Global Configuration Options
- [Global Configuration Options](global-configs.md)
"

# Write the Markdown content to the output file
echo -e "$markdown_content" > "$output_file"
echo "Markdown file created: $output_file"
