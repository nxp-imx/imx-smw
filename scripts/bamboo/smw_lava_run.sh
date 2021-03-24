#!/bin/bash
set -ex

function usage()
{
    cat << EOF

    *****************************************************
    * Usage of Security Middleware LAVA test run script *
    *****************************************************

    Script is preparing the LAVA environment and script
    to run LAVA test on a given platform.
    If it's a PR verification, run Release and Debug
    tests based on the PR built package.
    Else if it's not a PR run tests using Linux root
    file system libraries and tests.

    $(basename "$0") <platform>
      <platform> : Mandatory platform

EOF
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
fi

platform="$1"

cd "$bamboo_build_working_directory"/smw

eval "./scripts/smw_squad.sh install"

script_dir="$bamboo_build_working_directory"/lava/bambooIntegrationScripts
yaml_dir=./tests/lava

daytoday=$(date +%w)
PR=0
# Check if the branch is a PR
if [ ! -z "${bamboo_repository_pr_targetBranch+x}" ] ; then
    PR=1
fi

# Fetch all reports from LAVA
rm -rf logs && mkdir logs

squad_id=$(echo "$bamboo_planRepository_branchName" | tr / _)_${bamboo_buildNumber}
job_id=${bamboo_planKey}-${bamboo_buildNumber}

if [[ ${daytoday} == "$bamboo_weekly_day_run" ]] && [[ ${PR} == 0 ]]; then
    #
    # If executed on Sunday, assume it's a periodic weekly check not a code change
    #
    eval "./scripts/smw_squad.sh submit_uuu ${platform} \
          ${script_dir} ${yaml_dir} ${squad_id} job_name=${job_id}"
else
    package_url="https://bamboo1.sw.nxp.com/browse/${job_id}/artifact/shared"

    #
    # Test Release build
    #
    eval "./scripts/smw_squad.sh submit_uuu ${platform} ${script_dir} \
           ${yaml_dir} ${squad_id} package_url=${package_url}/package_rel \
           job_name=${job_id}"

    #
    # Test Debug build and retreive code coverage result
    #
    eval "./scripts/smw_squad.sh submit_uuu ${platform} ${script_dir} \
          ${yaml_dir} ${squad_id} coverage \
          package_url=${package_url}/package_deb \
          job_name=${job_id}"
fi


#
# Wait for LAVA execution results
#
eval "./scripts/smw_squad.sh result"
