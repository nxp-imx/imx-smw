#!/bin/bash
set -ex

# Define nexus default url
nexus_url="${bamboo_nexus_url:-"https://nl-nxrm.sw.nxp.com/repository"}"
nexus_dir="${bamboo_nexus_lava_dir:-"mougins-raw-public-artifacts/LAVA/smw"}"
job_name="${bamboo_planKey}-${bamboo_buildNumber}"
bamboo_plan="${bamboo_planKey:-"misc"}"

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

function check_url
{
    status=$(curl -I -s "$1" | head -n 1)
    if [[ -w ${status} ]]; then
      printf "File %s doesn't exist\n" "$1"
      exit 1
    fi
}

function gcda_upload_extract
{
    #
    # Upload gdca tarball and untar it in the
    # build directory
    #
    local gcda_filename="${platform}_${job_name}.tar.gz"
    local gcda_url="${nexus_url}/${nexus_dir}/${bamboo_plan}"

    check_url "${gcda_url}/${gcda_filename}"

    printf "Get the GCDA tarball file\n"
    eval "curl -O ${gcda_url}/${gcda_filename}"

    printf "Untar %s into %s\n" "$1" "$2"
    eval "tar -xvmf $1 -C $2"

    eval "curl -n -X DELETE ${gcda_url}/${gcda_filename}"
}

if [[ $# -lt 1 ]]; then
    usage
fi

platform=$1

#
# Read the gcno build file info
#
root_dir=
build_dir=
get_file_info root_dir "ROOT_DIR" "gcno_build_info.txt"
get_file_info build_dir "BUILD_DIR" "gcno_build_info.txt"

#
# Define code coverage directories
#
gcov_report="gcov_report"
gcov_out="./${gcov_report}"
gcno_dir="${root_dir}/${build_dir}"
gcda_dir="${root_dir}/${build_dir}"

lcov_tool="../lcov_tool"
gcda_tarball="${platform}_${job_name}.tar.gz"
gcda_tarball="${gcda_tarball// /_}"

# Go to the bamboo build directory where are the gcno files
eval "cd ${root_dir}"

gcda_upload_extract "${gcda_tarball}" "/"

#
# Install lcov tool
#
eval "./scripts/gcov-gen.sh install lcov=${lcov_tool}"

#
# Find where the toolchain is installed
#
toolchain_path=
get_file_info toolchain_path "TOOLCHAIN_BIN_PATH" "${build_dir}/CMakeCache.txt"

#
# Generate gcov report and tar it
#
eval "./scripts/gcov-gen.sh report gcno=${gcno_dir} gcda=${gcda_dir} \
       src=. nomerge out=${gcov_out} conf=./scripts/lcov.rc \
       lcov=${lcov_tool} gcov=${toolchain_path} title=\"SMW Code Coverage\""

#
# Copy generated report in current plan to publish artifact
#
eval "cp ${gcov_report}.tar.gz $bamboo_build_working_directory"
