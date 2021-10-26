#!/bin/bash
set -ex

bash_dir=$(dirname "${BASH_SOURCE[0]}")
source "${bash_dir}/smw_bamboo_config.sh"

trap exit_vvenv EXIT

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
      <deploy>   : [option] board binary deployement (default: 'uuu' or 'uboot')
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
opt_deploy=submit_uuu

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

            uuu)
                opt_deploy=submit_uuu
                ;;

            uboot)
                opt_deploy=submit
                ;;

            *)
                echo "Unknown argument \"${arg}\""
                usage
                ;;
        esac
        shift
    done
fi

#
# Start venv
#
start_vvenv

eval "./scripts/smw_squad.sh install"

script_lava_dir="$bamboo_build_working_directory/lava/bambooIntegrationScripts"
script_tools_dir="$bamboo_build_working_directory/tools"
yaml_dir=./scripts/lava

# Fetch all reports from LAVA
rm -rf logs && mkdir logs

squad_id=$(echo "$bamboo_planRepository_branchName" | tr / _)_${bamboo_buildNumber}

if [[ $(is_pr) -eq 0 ]] && [[ $(is_release_build) -eq 1 ]]; then
    #
    # If executed on selected weekly day, assume it's a periodic weekly don't
    # check code change neither do a code coverage report
    #

    if [[ -n ${opt_coverage} ]]; then exit 0; fi

    eval "./scripts/smw_squad.sh submit_uuu ${platform} \
          ${script_lava_dir} ${yaml_dir} ${squad_id} job_name=${job_name}"
else
    #
    # Test Release or Debug build and retrieve code coverage result if any
    #
    to_nexus_dir="to_nexus"
    plat_package="libsmw_package.tar.gz"
    pkg_name="pkg_${platform}_${opt_type}_${bamboo_buildNumber}.tar.gz"

    eval "mkdir -p ${to_nexus_dir}"
    eval "cp ./package/${plat_package} ./to_nexus/${pkg_name}"

    # Upload package to be tested in Nexus
    nexus_upload_artifacts "${script_tools_dir}" "${to_nexus_dir}" "${nexus_test_dir}"

    coverage_url=

    if [[ -n ${opt_coverage} ]]; then
        coverage_url="${nexus_test_full_path}/${platform}_${gcda_tarball}"
    fi

    eval "./scripts/smw_squad.sh ${opt_deploy} ${platform} ${script_lava_dir} \
          ${yaml_dir} ${squad_id} \
          package_url=${nexus_test_full_path}/${pkg_name} \
          coverage_url=${coverage_url} \
          job_name=${job_name}"
fi

#
# Wait for LAVA execution results
#
eval "./scripts/smw_squad.sh result"
