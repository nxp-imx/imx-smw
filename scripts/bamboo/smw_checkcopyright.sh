#!/bin/bash
# Check Copyright script
set -ex

bash_dir=$(dirname "${BASH_SOURCE[0]}")
source "${bash_dir}/smw_bamboo_config.sh"

cc_tool="${bash_dir}/../check-copyright.sh"

if [ ! -e "${cc_tool}" ]; then
    echo "WARNING: Check Copyright not run"
    exit 0
fi

# Check if the branch is a PR
if [[ $(is_pr) -eq 1 ]] ; then
    head_pr="origin/${bamboo_repository_pr_targetBranch}"
    head_src="origin/${bamboo_repository_pr_sourceBranch}"

    # Run check copyright on every commit of the PR
    ${cc_tool} --diff "${head_pr}" "${head_src}"
fi

