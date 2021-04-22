#!/bin/bash
set -e

function usage()
{
    cat << EOF

    ****************************************************
    * Usage of Security Middleware Bamboo build script *
    ****************************************************

    Script is building the overall Security Middleware project
    in Bamboo environment.
    SMW library, PKCS11 and all tests are built in Release and Debug
    mode.

    Then if build is done for a pull-request validation, packages
    for each build mode, all files used to run tests including
    built libraries.

    $(basename "$0") <arch> <platform> coverage
      <arch>     : Mandatory architecture aarch32 or aarch64
      <platform> : Mandatory platform
      coverage   : [optional] Enable the code coverage tool

EOF
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

arch="$1"
platform="$2"

shift 2

opt_coverage=

if [[ $# -ne 0 ]]; then
    for arg in "$@"
    do
        case ${arg} in
              coverage)
                opt_coverage="coverage"
                ;;

           *)
                echo "ERROR: Unknown argument \"${arg}\""
                usage
                ;;
        esac
        shift
    done
fi

build_release="build.${platform}_rel"
build_debug="build.${platform}_deb"

# Delete previous builds
rm -rf "${build_release}"
rm -rf "${build_debug}"

daytoday=$(date +%w)

# Check if the branch is a PR and it's daily build
if [ -z "${bamboo_repository_pr_targetBranch+x}" ]; then
    if [[ ${daytoday} == "$bamboo_weekly_day_run" ]]; then
        git clean -xdf
    fi
fi

export="./export"
# Delete seco export in case there is a change
if [[ -e "${export}/usr/include/hsm/" ]]; then
    rm -f "${export}/usr/include/seco_nvm.h"
    rm -f "${export}/usr/include/hsm/*.*"
    rm -f "${export}/usr/lib/seco_nvm_manager.a"
    rm -f "${export}/usr/lib/hsm_lib.a"
fi

#
# Configure, build and package Release build of all targets
#
eval "./scripts/smw_configure.sh ${build_release} ${arch} ${platform}"
eval "./scripts/smw_build.sh build out=${build_release}"
eval "./scripts/smw_build.sh package out=${build_release}"

#
# Configure, build and package Debug build of all targets
# Enable code coverage
#
eval "./scripts/smw_configure.sh ${build_debug} ${arch} ${platform}"
eval "./scripts/smw_build.sh configure out=${build_debug} \
      ${opt_coverage} debug verbose=4"
eval "./scripts/smw_build.sh build out=${build_debug}"
eval "./scripts/smw_build.sh package out=${build_debug}"

if [[ ! -z ${opt_coverage} ]]; then
    #
    # Create a tarball of all gnco files to create an artifact
    #
    gcno_tarball="gcno_${platform}.tar.gz"
    find "${build_debug}" -type f -name "*.gcno" -exec tar -czf "${gcno_tarball}" {} +

    #
    # Create text file with build information
    #
    echo "ROOT_DIR=$PWD" > "gcno_build_${platform}_info.txt"
    echo "BUILD_DIR=${build_debug}" >> "gcno_build_${platform}_info.txt"
    echo "GCNO_TARBALL=${gcno_tarball}" >> "gcno_build_${platform}_info.txt"
fi
