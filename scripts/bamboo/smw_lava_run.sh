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

    $(basename "$0") <platform> <type> coverage
      <platform> : Mandatory platform
      <type>     : [option] build type ('release' or 'debug', default: 'release')
      coverage   : [option] enable the code coverage tool

EOF
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

platform="$1"
shift

opt_type=rel
opt_coverage=

if [[ $# -ne 0 ]]; then
    for arg in "$@"
    do
        case ${arg} in
            coverage)
                opt_coverage="coverage"
                ;;

            debug)
                opt_type=deb
                ;;

            release)
                opt_type=rel
                ;;


            *)
                echo "Unknown argument \"${arg}\""
                usage
                ;;
        esac
        shift
    done
fi

eval "./scripts/smw_squad.sh install"

script_dir="$bamboo_build_working_directory"/lava/bambooIntegrationScripts
yaml_dir=./scripts/lava

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
    # If executed on Sunday, assume it's a periodic weekly don't
    # check code change neither do a code coverage report
    #
    eval "./scripts/smw_squad.sh submit_uuu ${platform} \
          ${script_dir} ${yaml_dir} ${squad_id} job_name=${job_id}"
else
    package_url="https://bamboo1.sw.nxp.com/browse/${job_id}/artifact/shared"
    plat_package="package_${platform}_${opt_type}"

    #
    # Test Release or Debug build and retrieve code coverage result if any
    #
    eval "./scripts/smw_squad.sh submit_uuu ${platform} ${script_dir} \
          ${yaml_dir} ${squad_id} ${opt_coverage} \
          package_url=${package_url}/${plat_package} \
          job_name=${job_id}"
fi


#
# Wait for LAVA execution results
#
eval "./scripts/smw_squad.sh result"
