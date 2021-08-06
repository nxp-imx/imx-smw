#!/bin/bash
set -ex

bash_dir=$(dirname "${BASH_SOURCE[0]}")
source "${bash_dir}/smw_bamboo_config.sh"

script_tools_dir="$bamboo_build_working_directory/tools"
test_dir="${nexus_test_top_dir}/${bamboo_plan}"

printf "NEXUS: Clean folder %s in folder %s\n" "${test_dir}" "${nexus_test_repo}"

eval "${script_tools_dir}/bamboo/nexus-clean-dir-recursively.sh ${nexus_test_repo} ${test_dir}"
