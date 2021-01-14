#!/bin/bash
set -eE
trap 'error ${LINENO}' ERR

script_name=$0

tmp_jobids="logs/jobids.txt"
smw_tmp_yaml="smw_tmp.yaml"
smw_setup_yaml="smw_setup.yaml"
smw_package_yaml="smw_package.yaml"
smw_ctest_yaml="smw_ctest.yaml"

devops_script="nexus-find-latest-db.sh"
lavacli_tool="lavacli"
def_squad_token="b786b334a22cd4734d4f180813f75bb7d725d491"

export PATH=/home/bamboo/.local/bin:$PATH

lava_url="${bamboo_lava_url:-https://lava.sw.nxp.com}"
lava_backend="${bamboo_lava_backend:-lava-https}"
lava_token="${bamboo_lava_token_secret:-}"
lava_user="${bamboo_lava_user:-squad-mougins}"
squad_token="${bamboo_squad_token:-${def_squad_token}}"
daily_build_version="${bamboo_daily_build_version:-"-2"}"
image_type="${bamboo_image_type:-"Linux_IMX_Core"}"
prefix_rootfs="${bamboo_prefix_rootfs:-"imx-image-core-"}"
prefix_kernel="${bamboo_prefix_kernel:-"Image-"}"
prefix_boot="${bamboo_prefix_boot:-"imx-boot-"}"
suffix_boot="${bamboo_suffix_boot:-"-sd.bin-flash_spl"}"
image_folder="${bamboo_image_folder:-"fsl-imx-internal-wayland"}"
nexus_repo="${bamboo_nexus_repo:-"IMX-raw_Linux_Internal_Daily_Build"}"

use_new_lava=0

function usage_lavacli()
{
    printf "\n"
    printf " To install and register lavacli user\n"
    printf "  %s install token=[token] user=[user]\n" "${script_name}"
    printf "    token = [optional] Lava token key\n"
    printf "    user  = [optional] Lava user name of the token key\n"
    printf "Note: optional parameters in bamboo environment require the variables\n"
    printf " \$bamboo_lava_token_secret for the token\n"
    printf " \$bamboo_lava_user for the user\n"
    printf "\n"
}

function usage_submit()
{
    printf "\n"
    printf "To submit a squad job\n"
    printf "  %s [action] platform script_dir yaml_dir squad_id package_url=[url] ctest_label=[label] job_name=[name]\n" "${script_name}"
    printf "    action      = [submit] boot with flashing MMC or [submit_uuu] boot with UUU\n"
    printf "    platform    = Platform name\n"
    printf "    script_dir  = Directory where %s is located\n" "${devops_script}"
    printf "    yaml_dir    = Directory where Lava jobs descriptions for Security Middleware are located\n"
    printf "    squad_id    = Suffix of squad tests, can contains more than one job\n"
    printf "    package_url = [optional] URL to custom Security Middleware package\n"
    printf "    ctest_label = [optional] CTest label\n"
    printf "    job_name    = [optional] Job name added in the job description\n"
    printf "\n"
}

function usage_result()
{
    printf "\n"
    printf " To wait and fetch squad result\n"
    printf "  %s result token=[token]\n" "${script_name}"
    printf "    token = [optional] Lava token key\n"
    printf "Note: optional parameter in bamboo environment require the variable\n"
    printf " \$bamboo_lava_token_secret for the token\n"
    printf "\n"
}

function usage()
{
    printf "\n"
    printf "*******************************************\n"
    printf " Usage of Security Middleware squad script \n"
    printf "*******************************************\n"
    usage_lavacli
    usage_submit
    usage_result
}

function parse_parameters
{
    for arg in "$@"
    do
      case $arg in
        token=*)
          lava_token="${arg#*=}"
          ;;

        user=*)
          lava_user="${arg#*=}"
          ;;

        package_url=*)
          opt_package_url="${arg#*=}"
          ;;

        ctest_label=*)
          opt_ctest_label="${arg#*=}"
          ;;

        job_name=*)
          opt_job_name="${arg#*=}"
          ;;

        *)
          usage
          exit 1
          ;;
      esac

      shift
    done
}

function check_directory
{
    if [[ ! -d "$1" ]]; then
      printf "%s is not a directory\n" "$1"
      exit 1
    fi
}

function check_file
{
    if [[ ! -e "$1"/"$2" ]]; then
      printf "Cannot find %s in %s\n" "$2" "$1"
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

function install_lavacli
{
    #
    # Get optional script command parameters
    #
    parse_parameters "$@"

    if [[ ! -x "$(command -v ${lavacli_tool})" ]]; then
      # Install lavacli & Create identity default
      pip3 install --user lavacli

      if [[ ! -x "$(command -v ${lavacli_tool})" ]]; then
        printf "lavacli installation error\n"
        exit 1
      fi
    fi

    if [[ -z ${lava_token} || -z ${lava_user} ]]; then
      printf "No User and/or Token defined to use lavacli\n"
      exit 1
    fi

    ${lavacli_tool} identities add \
    --token "${lava_token}" \
    --uri "${lava_url}/RPC2" \
    --username "${lava_user}" default

    exit 0
}

function squad_submit
{
    #
    # Get the mandatory parameters
    #
    if [[ $# -lt 4 ]]; then
      usage
      exit 0
    fi

    platform=$1
    script_dir=$2
    yaml_dir=$3
    squad_id=$4

    # Set the default job name in case not set
    opt_job_name=${platform}

    shift 4

    parse_parameters "$@"

    #
    # Define the Yaml replacement variable
    # depending on the platform
    #
    case ${platform} in
      imx8qxpc0mek)
        filename_bootimage=${prefix_boot}${platform}${suffix_boot}
        filename_dtb=imx8qxp-mek.dtb
        filename_kernel=${prefix_kernel}${platform}.bin
        rootfs_name=${prefix_rootfs}${platform}
        BOARD_ID=imx8qxpc0mek
        if [[ ${use_new_lava} -eq 1 ]]; then
            LAVA_DEVICE_TYPE=imx8qxp-mek
        else
            LAVA_DEVICE_TYPE=fsl-imx8qxp-c0-mek-linux
        fi
        UBOOT_MMC_BLK=0x40
        UBOOT_MMC_CNT=0x1000
        ;;

      *)
        printf "Platform %s not supported\n" "${platform}"
        printf "Supported platforms: %s " "imx8qxpc0mek"
        printf "\n"
        usage
        exit 1
        ;;
    esac

    check_directory "${script_dir}"
    check_directory "${yaml_dir}"

    check_file "${script_dir}" "${devops_script}"

    PACKAGE_URL=${opt_package_url}

    if [[ ! -z ${opt_ctest_label} ]]; then
      CTEST_LABEL="-L ${opt_ctest_label}"
    fi

    cat "${yaml_dir}"/"${smw_setup_yaml}" > "${yaml_dir}"/"${smw_tmp_yaml}"
    if [[ ! -z ${opt_package_url} ]]; then
      check_url "${opt_package_url}/libsmw_package.tar.gz"

      cat "${yaml_dir}"/"${smw_package_yaml}" >> "${yaml_dir}"/"${smw_tmp_yaml}"
    fi

    # SMW Ctest execution
    cat "${yaml_dir}"/"${smw_ctest_yaml}" >> "${yaml_dir}"/"${smw_tmp_yaml}"

    filename_job="${yaml_dir}"/"${smw_tmp_yaml}"
    check_file "${yaml_dir}" "${smw_tmp_yaml}"

    sed -i "s|REPLACE_UBOOT_MMC_BLK|$UBOOT_MMC_BLK|" "${filename_job}"
    sed -i "s|REPLACE_UBOOT_MMC_CNT|$UBOOT_MMC_CNT|" "${filename_job}"

    if [[ ! -z ${opt_package_url} ]]; then
      sed -i "s|REPLACE_PACKAGE_URL|$PACKAGE_URL|" "${filename_job}"
    fi
    sed -i "s|REPLACE_CTEST_LABEL|$CTEST_LABEL|" "${filename_job}"

    SQUAD_GROUP="mougins-devops"
    if [[ ${use_new_lava} -eq 1 ]]; then
      JOB_TAG=mougins-docker-soplpuats50
    else
      JOB_TAG=daas_mougins
    fi
    SQUAD_SLUG=SMW

    "${script_dir}"/"${devops_script}" \
              -l nl \
              -r "${nexus_repo}" \
              -i "${image_type}" \
              -j "${image_folder}" \
              -d "${filename_dtb}" \
              -k "${filename_kernel}" \
              -m "${filename_bootimage}" \
              -b "${rootfs_name}" \
              -y "${filename_job}" \
              -o "${opt_job_name}" \
              -v "$LAVA_DEVICE_TYPE" \
              -t "$JOB_TAG" \
              -n "${daily_build_version}"

    if [[ ! -z ${opt_package_url} ]]; then
        printf "PACKAGE_URL = %s\n" "$PACKAGE_URL"
    fi

    if [[ ! -x "$(command -v ${lavacli_tool})" ]]; then
      printf "lavacli not installed\n"
      exit 1
    fi

    sleep 5

    # Return job id submitted to LAVA
    job_id="$(${lavacli_tool} jobs submit "${filename_job}")"
    printf "Job ID %s\n" "${job_id}"

    if [[ ${job_id} == "Unable to submit" ]]; then
      printf "Unable to submit job for %s\n" "${platform}"
      exit 1
    fi

    squad_url_suffix="${SQUAD_GROUP}"/"${SQUAD_SLUG}"/SMW_"${squad_id}"/"${BOARD_ID}"

    curl --noproxy "*" \
         --header "Auth-Token: ${squad_token}" \
         --form backend="${lava_backend}" \
         --form testjob_id="${job_id}" \
         "http://squad.sw.nxp.com/api/watchjob/${squad_url_suffix}"

    echo "${platform} ${job_id}" >> "${tmp_jobids}"
}

function squad_result
{
    local exit_val=0

    if [[ ! -x "$(command -v ${lavacli_tool})" ]]; then
      printf "lavacli not installed"
      exit 1
    fi

    check_file "." "${tmp_jobids}"

    #
    # Get optional script command parameters
    #
    parse_parameters "$@"

    if [[ -z ${lava_token} ]]; then
       printf "No Token defined to use lavacli\n"
       exit 1
    fi

    while IFS= read -r line; do
      elem=($line)
      platform="${elem[0]}"
      job_id="${elem[1]}"

      printf "Check jobid %s on platform %s\n" "${job_id}" "${platform}"

      # Wait for test to finish
      wait_res="$(${lavacli_tool} jobs wait "${job_id}" --polling 60 --timeout 3600 || true)"

      case $wait_res in
        *"timeout"*)
           printf "Error: %s\n" "${wait_res}"
           exit_val=1
           ;;

        *"Unable"*)
           printf "Error: %s\n" "${wait_res}"
           exit_val=1
           ;;

         *)
           ;;
      esac

      # Fetch Juint report
      curl -X GET -H "Authorization: Token ${lava_token}" \
          --output logs/"${platform}"_"${job_id}".xml \
          "${lava_url}"/api/v0.2/jobs/"${job_id}"/junit/

      # Fetch logs
      ${lavacli_tool} jobs logs "${job_id}" > logs/"${platform}"_"${job_id}"_log.txt
    done < "${tmp_jobids}"

    if grep -q "'result': 'fail'" logs/*.txt; then
      exit 1
    fi

    if grep -q "RESULT=fail" logs/*.txt; then
      exit 1
    fi

    exit ${exit_val}
}

if [[ $# -eq 0 ]]; then
  usage
  exit 0
fi

opt_action=$1
shift

if [[ ${lava_url} == "https://lava.sw.nxp.com" ]]; then
  use_new_lava=1
fi

case $opt_action in
  install)
    install_lavacli "$@"
    ;;

  submit)
    squad_submit "$@"
    ;;

  submit_uuu)
    smw_setup_yaml="smw_setup_uuu.yaml"
    squad_submit "$@"
    ;;

  result)
    squad_result "$@"
    ;;

  *)
    usage
    ;;
esac
