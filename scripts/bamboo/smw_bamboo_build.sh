#!/bin/bash
set -ex

bash_dir=$(dirname "${BASH_SOURCE[0]}")
source "${bash_dir}/smw_bamboo_config.sh"

trap exit_vvenv EXIT

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
      doc        : [optional] Archive documentation

EOF
}

if [[ $# -lt 2 ]]; then
    usage
    exit 1
fi

arch="$1"
platform="$2"

shift 2

opt_coverage=
opt_doc=0

if [[ $# -ne 0 ]]; then
    for arg in "$@"
    do
        case ${arg} in
              coverage)
                opt_coverage="coverage"
                ;;

              doc)
                opt_doc=1
                ;;

              *)
                echo "WARNING: Unknown argument \"${arg}\""
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

# Check if the branch is not a PR and it's daily build
if [[ $(is_pr) -eq 0 ]] && [[ $(is_release_build) -eq 1 ]]; then
    git clean -xdf
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
# Start venv
#
start_vvenv

# Install python package to build OPTEE
eval "python3 -m pip install pyelftools pycryptodomex"

#
# Configure, build and package Release build of all targets
#
eval "./scripts/smw_configure.sh ${build_release} ${arch} ${platform}"
eval "./scripts/smw_build.sh build out=${build_release}"
eval "./scripts/smw_build.sh package out=${build_release}"
eval "./scripts/smw_build.sh build docs out=${build_release} format=\"all\""

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

#
# Archive documentation
#
mnt_server="/mnt/ubuntuserver/SharedFiles/security_middleware"
doc_path="${build_release}/Documentations/API"
doc_dir_root="Documentations"
doc_dir_html="html"
doc_dir_pdf="latex"
doc_arch="${mnt_server}/${doc_dir_root}"

if [[ $(is_pr) -eq 0 && $(is_release_build) -eq 1 ]]; then
    if [[ ${opt_doc} -eq 1 ]]; then
        doc_ver=$(get_lib_version)
        doc_arch="${doc_arch}/${doc_ver}"
        printf "Archiving documentation version %s ..." "${doc_ver}"
        rm -rf "${doc_arch}"
        eval "mkdir -p ${doc_arch}"
        eval "cp -r ${doc_path}/${doc_dir_html} ${doc_arch}/."
        if [[ -n "$(find ${doc_path}/${doc_dir_pdf} -maxdepth 1 -name '*.pdf' -type f -print -quit)" ]]; then
            eval "mkdir ${doc_arch}/${doc_dir_pdf}"
            eval "cp ${doc_path}/${doc_dir_pdf}/*.pdf ${doc_arch}/${doc_dir_pdf}/."
        fi
    fi
fi
