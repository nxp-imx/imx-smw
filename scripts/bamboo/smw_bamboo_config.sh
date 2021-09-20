#!/bin/bash
# Define all bamboo common share function/macro and constants

# Flag indicating if python virtual environment activated or not
python_vvenv_on=0

# Get bamboo variables
bamboo_plan="${bamboo_planKey:-"misc"}"

nexus_test_url="${bamboo_nexus_test_url:-"https://nl-nxrm.sw.nxp.com"}"
nexus_test_url_get="${nexus_test_url}/repository"
nexus_test_repo="${bamboo_nexus_test_repo:-"mougins-raw-public-artifacts"}"
nexus_test_top_dir="${bamboo_nexus_test_top_dir:-"SMW_Test"}"
nexus_test_dir="${nexus_test_repo}/${nexus_test_top_dir}/${bamboo_plan}"
nexus_test_full_path="${nexus_test_url_get}/${nexus_test_dir}"

job_name=${bamboo_plan}-${bamboo_buildNumber}

gcda_tarball="${job_name}_gcda.tar.gz"
gcda_tarball="${gcda_tarball// /_}"

#
# Python virtual environment
#
# End vvenv
function exit_vvenv {
    if [[ ${python_vvenv_on} -eq 1 ]]; then
        deactivate
    fi
}

# Start venv
function start_vvenv {
    venv_dir="venv_smw"
    eval "python3 -m venv ${venv_dir}"
    eval "source ${venv_dir}/bin/activate"

    python_vvenv_on=1
}

#
# Common scripts functions
#
function check_url
{
    status=$(curl --head --silent "$1" | head -n 1)
    if echo "$status" | grep -q 404; then
      printf "File %s doesn't exist\n" "$1"
      exit 1
    fi
}

function nexus_upload_artifacts
{
    script_dir=$1
    src=$2
    dst=$3

    printf "NEXUS: Uploading folder %s in folder %s\n" "${src}" "${dst}"

    eval "$1/bamboo/bamboo-to-nexus-upload.sh ${src} ${dst} ${nexus_test_url}"
}

function is_pr
{
    # Check if the branch is a PR or not
   if [[ -z "${bamboo_repository_pr_targetBranch+x}" ]] ; then
       echo 0
   else
       echo 1
   fi
}

function is_release_build
{
    local daytoday=$(date +%w)

    if [[ ${daytoday} == "$bamboo_weekly_day_run" ]]; then
        echo 1
    elif [[ -n "$bamboo_release_build" && "$bamboo_release_build" -eq 1 ]]; then
        echo 1
    else
        echo 0
    fi
}

function get_lib_version
{
    # Get the version last part of branch name after `_`
    # Branch name must be "release/blabla_1.x" to get the version "1.x"
    local br_name="${bamboo_planRepository_branchName}"

    if [[ "${br_name}" =~ ^"release//"* && "${br_name}" =~ .*"_".* ]]; then
        echo "${br_name##*_}"
    else
        echo "latest"
    fi
}