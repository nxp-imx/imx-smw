#!/bin/bash
set -eE
trap 'error ${LINENO}' ERR

script_name=$0

smw_tmp_yaml="smw_tmp.yaml"
smw_setup_yaml="smw_setup.yaml"
smw_package_yaml="smw_package.yaml"
smw_ctest_yaml="smw_ctest.yaml"

devops_script="nexus-find-latest-db.sh"

function usage()
{
    printf "\n"
    printf "*******************************************\n"
    printf " Usage of Security Middleware squad script \n"
    printf "*******************************************\n"
    printf "\n"
    printf "To submit a squad job\n"
    printf "  %s platform_name script_dir yaml_dir package_url=[url] ctest_label=[label]\n" "${script_name}"
    printf "    platform_name = Platform name\n"
    printf "    script_dir    = Directory where %s is located\n" "${devops_script}"
    printf "    yaml_dir      = Directory where Lava jobs descriptions for Security Middleware are located\n"
    printf "    package_url   = [optional] URL to custom Security Middleware package\n"
    printf "    ctest_label   = [optional] CTest label\n"
    printf "\n"
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

if [[ $# -lt 3 ]]; then
    usage
    exit 0
fi

platform=$1
script_dir=$2
yaml_dir=$3

case $platform in
    imx8qxpc0mek)
        FILENAME_BOOTIMAGE=imx-boot-imx8qxpc0mek-sd.bin-flash
        FILENAME_DTB=imx8qxp-mek.dtb
        FILENAME_KERNEL=Image-imx8qxpc0mek.bin
        IMAGE_NAME=imx-image-core-imx8qxpc0mek
        BOARD_ID=imx8qxpc0mek
        LAVA_DEVICE_TYPE=fsl-imx8qxp-c0-mek-linux
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

shift 3

for arg in "$@"
do
    case $arg in
        package_url=*)
            opt_package_url="${arg#*=}"
            ;;

        ctest_label=*)
            opt_ctest_label="${arg#*=}"
            ;;

        *)
            printf "Unknown option %s\n" "$arg"
            usage
            exit 1
            ;;
    esac

    shift
done

PACKAGE_URL=${opt_package_url}
if [[ ! -z ${opt_ctest_label} ]]; then
    CTEST_LABEL="-L ${opt_ctest_label}"
fi

cat "${yaml_dir}"/"${smw_setup_yaml}" > "${yaml_dir}"/"${smw_tmp_yaml}"
if [[ ! -z ${opt_package_url} ]]; then
    cat "${yaml_dir}"/"${smw_package_yaml}" >> "${yaml_dir}"/"${smw_tmp_yaml}"
fi
cat "${yaml_dir}"/"${smw_ctest_yaml}" >> "${yaml_dir}"/"${smw_tmp_yaml}"
JOB_FILE="${yaml_dir}"/"${smw_tmp_yaml}"
check_file "${yaml_dir}" "${smw_tmp_yaml}"

sed -i "s|REPLACE_UBOOT_MMC_BLK|$UBOOT_MMC_BLK|" "$JOB_FILE"
sed -i "s|REPLACE_UBOOT_MMC_CNT|$UBOOT_MMC_CNT|" "$JOB_FILE"

if [[ ! -z ${opt_package_url} ]]; then
    sed -i "s|REPLACE_PACKAGE_URL|$PACKAGE_URL|" "$JOB_FILE"
fi
sed -i "s|REPLACE_CTEST_LABEL|$CTEST_LABEL|" "$JOB_FILE"

NEXUS_REPO=IMX-raw_Linux_Internal_Daily_Build
IMAGE_TYPE=Linux_IMX_Core
ROOTFS_FOLDER_NAME=fsl-imx-internal-wayland
JOB_TAG=daas_mougins
SQUAD_GROUP="mougins-devops"
SQUAD_SLUG=SMW
LAVA_JOB_NAME="SMW CI on $BOARD_ID"

"${script_dir}"/"${devops_script}" \
          -l nl \
          -r "$NEXUS_REPO" \
          -i "$IMAGE_TYPE" \
          -j "$ROOTFS_FOLDER_NAME" \
          -d "$FILENAME_DTB" \
          -k "$FILENAME_KERNEL" \
          -m "$FILENAME_BOOTIMAGE" \
          -b "$IMAGE_NAME" \
          -y "$JOB_FILE" \
          -o "$LAVA_JOB_NAME" \
          -v "$LAVA_DEVICE_TYPE" \
          -t "$JOB_TAG" \
          -n -2

if [[ ! -z ${opt_package_url} ]]; then
    printf "PACKAGE_URL = %s\n" "$PACKAGE_URL"
fi

# use current date to tag builds in SQUAD
BUILD_DATE=$(date '+%Y-%m-%d-%H-%M-%S')
printf "BUILD_DATE  = %s\n" "$BUILD_DATE"

curl --noproxy "*" --header "Auth-Token: b786b334a22cd4734d4f180813f75bb7d725d491" --form backend=LAVA-MASTER \
     --form definition=@"$JOB_FILE" http://squad.sw.nxp.com/api/submitjob/"${SQUAD_GROUP}"/"${SQUAD_SLUG}"/"${BUILD_DATE}"_smw/"${BOARD_ID}"
