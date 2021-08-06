#!/bin/bash
set -ex

bash_dir=$(dirname "${BASH_SOURCE[0]}")
source "${bash_dir}/smw_bamboo_config.sh"

trap exit_vvenv EXIT

function usage()
{
    cat << EOF

    *****************************************************
    * Usage of Security Middleware Code Coverage script *
    *****************************************************

    Script is generating the GCOV code coverage report
    in Bamboo environment.

    It uploads the tarball file of the gcda data file
    generated during the test executing.

    $(basename "$0") <platform>
      <platform> : Mandatory platform

EOF
    exit 1
}

function get_file_info()
{
    local pattern="$2"
    local filename="$3"

    while read -r line
    do
        case $line in
            ${pattern}*)
                IFS='=' read -ra split_line <<< "$line"
                break
                ;;
        esac
    done < "${filename}"

    if [[ ${#split_line[@]} -ge 2 ]]; then
        eval "$1=${split_line[1]}"
    else
        printf "${pattern} not found in %s\n" "${filename}"
        exit 1
    fi
}

function tarball_extract
{
    printf "Untar %s into %s\n" "$1" "$2"
    eval "tar -xvmf $1 -C $2"
}

function gcda_upload_extract
{
    #
    # Upload gdca tarball and untar it in the
    # build directory
    #
    local gcda_filename="$1"

    check_url "${nexus_test_full_path}/${gcda_filename}"

    printf "Get the GCDA tarball file\n"
    eval "curl -O ${nexus_test_full_path}/${gcda_filename}"

    tarball_extract "${gcda_filename}" "$2"
}

if [[ $# -lt 1 ]]; then
    usage
fi

# Check if the branch is not a PR and it's daily build
if [[ $(is_pr) -eq 0 ]] && [[ $(is_weekly_build) -eq 1 ]]; then
    # Don't run code coverage
    exit 0
fi

#
# Start venv
#
start_vvenv

platform=$1

#
# Read the gcno build file info
#
root_dir=
build_dir=
gcno_tarball=
gcno_info="../gcno_build_${platform}_info.txt"
get_file_info root_dir "ROOT_DIR" "${gcno_info}"
get_file_info build_dir "BUILD_DIR" "${gcno_info}"
get_file_info gcno_tarball "GCNO_TARBALL" "${gcno_info}"

#
# Define code coverage directories
#
gcov_report="gcov_report_${platform}"
gcov_out="./${gcov_report}"
lcov_tool="../lcov_tool"

#
# Check if gcno tarball exist and copy it locally
#
if [[ ! -e "${root_dir}/${gcno_tarball}" ]]; then
    printf "gcno tarball not found"
    exit 1
fi

eval "cp ${root_dir}/${gcno_tarball} ."

# Make directory to uncompress gcno and gcda files
gcov_data="./gcov_data"
if [[ -e "${gcov_data}" ]]; then
    eval "rm -rf ${gcov_data}"
fi

eval "mkdir -p ${gcov_data}${root_dir}"

tarball_extract "${gcno_tarball}" "${gcov_data}${root_dir}"
gcda_upload_extract "${platform}_${gcda_tarball}" "${gcov_data}"

gcno_dir="${gcov_data}/${root_dir}/${build_dir}"
gcda_dir="${gcov_data}/${root_dir}/${build_dir}"

#
# Install lcov tool
#
eval "./scripts/gcov-gen.sh install lcov=${lcov_tool}"

#
# Find where the toolchain is installed
#
toolchain_path=
get_file_info toolchain_path "TOOLCHAIN_BIN_PATH" \
              "${root_dir}/${build_dir}/CMakeCache.txt"

#
# Generate gcov report and tar it
#
eval "./scripts/gcov-gen.sh report gcno=${gcno_dir} gcda=${gcda_dir} \
       src=. nomerge out=${gcov_out} conf=./scripts/lcov.rc \
       lcov=${lcov_tool} gcov=${toolchain_path} title=\"SMW Code Coverage\""
