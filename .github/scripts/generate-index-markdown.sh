#!/bin/bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Output file name
output_file="docs/index.md"
template_file="${DIR?}"/index-template.md

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
    echo "\n### Auth Benchmark Tests\n$auth_tests_list\n\n### Secret Benchmark Tests\n$secret_tests_list\n\n### System Tests\n$system_tests_list"
}

# Read the template file
template_content=$(<"$template_file")

# Generate the Markdown content
markdown_content="${template_content//\{\{test_lists_placeholder\}\}/$(generate_tests_list)}"

# Write the Markdown content to the output file
echo -e "$markdown_content" > "$output_file"
echo "Markdown file created: $output_file"
