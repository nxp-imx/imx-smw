#!/bin/bash
set -eE
trap 'error ${LINENO}' ERR

script_name=$0

tmp_jobids="logs/jobids.txt"
smw_tmp_yaml="smw_tmp.yaml"
smw_setup_yaml="smw_setup"
smw_package_yaml="smw_package.yaml"
smw_ctest_yaml="smw_ctest.yaml"
pkcs11_ctest_yaml="pkcs11_ctest.yaml"
code_coverage_yaml="code_coverage.yaml"

devops_script="nexus-find-latest-db.sh"
lavacli_tool="lavacli"

export PATH=/home/bamboo/.local/bin:$PATH

lava_url="${bamboo_lava_url:-"https://lava.sw.nxp.com"}"
lava_backend="${bamboo_lava_backend:-lava-https}"
lava_token="${bamboo_lava_token_secret:-}"
lava_user="${bamboo_lava_user:-squad-mougins}"
squad_token="${bamboo_squad_token_secret:-}"
daily_build_version="${bamboo_daily_build_version:-"-2"}"
image_type="${bamboo_image_type:-"Linux_IMX_Core"}"
prefix_rootfs="${bamboo_prefix_rootfs:-"imx-image-core-"}"
prefix_image="${bamboo_prefix_image:-"Image-"}"
prefix_zimage="${bamboo_prefix_zimage:-"zImage-"}"
prefix_imx_boot="${bamboo_prefix_imx_boot:-"imx-boot-"}"
suffix_imx_boot="${bamboo_suffix_boot:-"-sd.bin-flash"}"
prefix_u_boot="${bamboo_prefix_u_boot:-"u-boot-"}"
suffix_u_boot="${bamboo_suffix_boot:-"_sd-optee.imx"}"
image_folder="${bamboo_image_folder:-"fsl-imx-internal-wayland"}"
nexus_repo="${bamboo_nexus_repo:-"IMX-raw_Linux_Internal_Daily_Build"}"
nexus_url="${bamboo_nexus_url:-"https://nl-nxrm.sw.nxp.com/repository"}"
nexus_dir="${bamboo_nexus_lava_dir:-"mougins-raw-public-artifacts/LAVA/smw"}"
bamboo_plan="${bamboo_planKey:-"misc"}"

opt_coverage=0
ctest_label=""

platforms_list=(
    imx8mmevk \
    imx7dsabresd \
    imx8qxpc0mek)

function display_platforms()
{
    printf "Supported platforms:\n"
    for plat in "${platforms_list[@]}"
    do
        printf "%s\n" "${plat}"
    done
    printf "\n"
}

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
    printf "  %s [action] platform script_dir yaml_dir"  "${script_name}"
    printf " squad_id coverage package_url=[url] ctest_label=[label]"
    printf " job_name=[name] token=[token]\n"
    printf "    action      = [submit] boot with flashing MMC or [submit_uuu]"
    printf " boot with UUU\n"
    printf "    platform    = Platform name\n"
    printf "    script_dir  = Directory where %s is located\n" "${devops_script}"
    printf "    yaml_dir    = Directory where Lava jobs descriptions for"
    printf " Security Middleware are located\n"
    printf "    squad_id    = Suffix of squad tests, can contains more than one job\n"
    printf "    coverage    = [optional] Upload Code Coverage result\n"
    printf "    package_url = [optional] URL to custom Security Middleware package\n"
    printf "    ctest_label = [optional] CTest label\n"
    printf "    job_name    = [optional] Job name added in the job description\n"
    printf "    token       = [optional] Squad token key\n"
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

    exit 1
}

function parse_parameters
{
    for arg in "$@"
    do
      case $arg in
        token=*)
          opt_token="${arg#*=}"
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

        coverage)
          opt_coverage=1
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

    if [[ ! -z ${opt_token} ]]; then
      lava_token="{opt_token}"
    fi

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
    local nexus_find_args=

    #
    # Get the mandatory parameters
    #
    if [[ $# -lt 4 ]]; then
      usage
    fi

    platform=$1
    script_dir=$2
    yaml_dir=$3
    squad_id=$4

    # Set the default job name in case not set
    opt_job_name=${platform}

    shift 4

    parse_parameters "$@"

    if [[ ! -z ${opt_token} ]]; then
      squad_token="{opt_token}"
    fi

    if [[ -z ${squad_token} ]]; then
      printf "No Token defined to use squad\n"
      exit 1
    fi

    nexus_find_args="-l nl -nosdcard -r ${nexus_repo} "
    nexus_find_args="${nexus_find_args} -i ${image_type}"
    nexus_find_args="${nexus_find_args} -j ${image_folder}"
    nexus_find_args="${nexus_find_args} -o ${opt_job_name}"
    nexus_find_args="${nexus_find_args} -t mougins-public"
    nexus_find_args="${nexus_find_args} -n ${daily_build_version}"

    #
    # Define the Yaml replacement variable
    # depending on the platform
    #
    case ${platform} in
      imx8qxpc0mek)
        bootimage="-m ${prefix_imx_boot}${platform}${suffix_imx_boot}_spl"
        nexus_find_args="${nexus_find_args} -d imx8qxp-mek.dtb"
        nexus_find_args="${nexus_find_args} -k ${prefix_image}${platform}.bin"
        kernel_type="image"
        nexus_find_args="${nexus_find_args} -b ${prefix_rootfs}${platform}"
        nexus_find_args="${nexus_find_args} -v imx8qxp-mek"
        uboot_mmc_blk="0x40"
        uboot_mmc_cnt="0x1000"
        ;;

      imx8mmevk)
        bootimage="-m ${prefix_imx_boot}${platform}${suffix_imx_boot}_evk"
        nexus_find_args="${nexus_find_args} -d imx8mm-evk.dtb"
        nexus_find_args="${nexus_find_args} -k ${prefix_image}${platform}.bin"
        kernel_type="image"
        nexus_find_args="${nexus_find_args} -b ${prefix_rootfs}${platform}"
        nexus_find_args="${nexus_find_args} -v imx8mm-evk"
        uboot_mmc_blk="0x42"
        uboot_mmc_cnt="0x1000"
        ;;

      imx7dsabresd)
        smw_setup_yaml="${smw_setup_yaml}_tee"
        bootimage="-u ${prefix_u_boot}${platform}${suffix_u_boot}"
        nexus_find_args="${nexus_find_args} -d imx7d-sdb.dtb"
        nexus_find_args="${nexus_find_args} -k ${prefix_zimage}imx6ul7d.bin"
        kernel_type="uimage"
        nexus_find_args="${nexus_find_args} -b ${prefix_rootfs}imx6ul7d"
        nexus_find_args="${nexus_find_args} -v imx7d-sdb"
        nexus_find_args="${nexus_find_args} -s uTee-7dsdb"
        uboot_mmc_blk="0x2"
        uboot_mmc_cnt="0x800"
        ;;

      *)
        printf "Platform %s not supported\n" "${platform}"
        display_platforms
        usage
        ;;
    esac

    nexus_find_args="${nexus_find_args} ${bootimage}"

    check_directory "${script_dir}"
    check_directory "${yaml_dir}"

    check_file "${script_dir}" "${devops_script}"

    if [[ ! -z ${opt_ctest_label} ]]; then
      ctest_label="-L ${opt_ctest_label}"
    fi

    cat "${yaml_dir}/${smw_setup_yaml}.yaml" > "${yaml_dir}/${smw_tmp_yaml}"
    if [[ ! -z ${opt_package_url} ]]; then
      check_url "${opt_package_url}/libsmw_package.tar.gz"

      cat "${yaml_dir}/${smw_package_yaml}" >> "${yaml_dir}/${smw_tmp_yaml}"
    fi

    {
        # SMW ctest execution
        cat "${yaml_dir}/${smw_ctest_yaml}"
        # PKCS11 ctest execution
        cat "${yaml_dir}/${pkcs11_ctest_yaml}"
    } >> "${yaml_dir}/${smw_tmp_yaml}"

    if [[ ${opt_coverage} -eq 1 ]]; then
      # If code coverage enabled
      gcda_tarball="${platform}_${opt_job_name}.tar.gz"
      gcda_tarball="${gcda_tarball// /_}"
      cat "${yaml_dir}/${code_coverage_yaml}" >> "${yaml_dir}/${smw_tmp_yaml}"
    fi

    filename_job="${yaml_dir}"/"${smw_tmp_yaml}"
    check_file "${yaml_dir}" "${smw_tmp_yaml}"

    sed -i "s|REPLACE_UBOOT_MMC_BLK|${uboot_mmc_blk}|" "${filename_job}"
    sed -i "s|REPLACE_UBOOT_MMC_CNT|${uboot_mmc_cnt}|" "${filename_job}"
    sed -i "s|REPLACE_KERNEL_TYPE|${kernel_type}|" "${filename_job}"

    if [[ ! -z ${opt_package_url} ]]; then
      sed -i "s|REPLACE_PACKAGE_URL|${opt_package_url}|" "${filename_job}"
    fi
    sed -i "s|REPLACE_CTEST_LABEL|${ctest_label}|" "${filename_job}"

    if [[ ${opt_coverage} -eq 1 ]]; then
      upload_url="${nexus_url}/${nexus_dir}"
      if [[ ! -z ${bamboo_plan} ]]; then
          upload_url="${upload_url}/${bamboo_plan}"
      fi
      sed -i "s|REPLACE_GCDA_FILE|${gcda_tarball}|" "${filename_job}"
      sed -i "s|REPLACE_UPLOAD_URL|${upload_url}|" "${filename_job}"
    fi

    squad_group="mougins-devops"
    squad_slug=SMW

    nexus_find_args="${nexus_find_args} -y ${filename_job}"

    eval "${script_dir}/${devops_script} ${nexus_find_args}"

    if [[ ! -z ${opt_package_url} ]]; then
        printf "PACKAGE_URL = %s\n" "${opt_package_url}"
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

    squad_url_suffix="${squad_group}"/"${squad_slug}"/SMW_"${squad_id}"/"${platform}"

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
fi

opt_action=$1
shift

case $opt_action in
  install)
    install_lavacli "$@"
    ;;

  submit)
    squad_submit "$@"
    ;;

  submit_uuu)
    smw_setup_yaml="smw_setup_uuu"
    squad_submit "$@"
    ;;

  result)
    squad_result "$@"
    ;;

  *)
    usage
    ;;
esac
