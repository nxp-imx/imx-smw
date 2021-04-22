#!/bin/bash
# Checkpatch script
# Install checkpatch in .tmp directory

set -ex

PR=0

# Remove previous checkpach to get the latest version
if [ -e ".tmp/checkpatch.pl" ]; then
    rm ".tmp/checkpatch.pl"
fi

cp_tool="./scripts/checkpatch.sh"

source ${cp_tool} --install

# Check if the branch is a PR
if [ ! -z "${bamboo_repository_pr_targetBranch+x}" ] ; then
    PR=1
    head_pr="origin/${bamboo_repository_pr_targetBranch}"
    head_src="origin/${bamboo_repository_pr_sourceBranch}"
fi

if [[ ${PR} -eq 0 ]]; then
    # If it is not a PR, run checkpatch on the top commit only
    ${cp_tool} HEAD
else
    cp_error=0

    # Run checkpatch on every commit of the PR
    # We could do only a checkdiff but running checkpatch on every single
    # commit help to identify which commit triggers checkpatch
    for c in $(git rev-list "${head_pr}..${head_src}")
    do
        printf "========================================================\n"
        # If checkpatch fails, assign cp_error to 1
        ${cp_tool} "$c" || cp_error=1
        printf "========================================================\n"
    done

    if [[ ${cp_error} -eq 1 ]]; then
        exit 1
    fi
fi
