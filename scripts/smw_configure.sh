#!/bin/bash
set -e

function check_directory()
{
    declare -n mydir=$1
    mydir="${mydir/\~/$HOME}"

    if [[ ! -d "${mydir}" ]]; then
        pr_err "${mydir} is not a directory"
    fi
}

function usage()
{
    cat << EOF

    *******************************************************
    * Usage of Security Middleware build configure script *
    *******************************************************

    Script is configuring the Security Middleware project enabling
    all modules and setuping the external dependencies.
    Let build type as default Release type.

    CAUTION: We assume this script is executed from the SMW top level
    source code directory where the output build directory <dir>
    will be created.

    $(basename "$0") <dir> <arch> <platform> toolpath=[dir]
      <dir>      : Mandatory output build directory
      <arch>     : Mandatory architecture aarch32 or aarch64
      <platform> : Mandatory i.MX platform name (use coverity to run coverity tool)
      <toolpath> : [Optional] Toolchain path where installed

EOF
    exit 1
}

if [[ $# -lt 3 ]]; then
    usage
fi

out=$1
arch="arch=$2"
platform="$3"
shift 3

#
# Convert platform to optee platform
#
optee_plat=
opt_seco=0
opt_ele=0
case ${platform} in
  imx93evk)
    optee_plat="imx-mx93evk"
    opt_ele=1
    ;;

  imx8qxpc0mek)
    optee_plat="imx-mx8qxpmek"
    opt_seco=1
    ;;

  imx8ulpevk)
    optee_plat="imx-mx8ulpevk"
    opt_ele=1
    ;;

  imx8mmevk)
    optee_plat="imx-mx8mmevk"
    ;;

  imx7dsabresd)
    optee_plat="imx-mx7dsabresd"
    ;;

  coverity)
    if [[ ${arch} =~ "aarch32" ]]; then
      optee_plat="imx-mx7dsabresd"
    else
      optee_plat="imx-mx93evk"
      opt_seco=1
      opt_ele=1
    fi
    ;;

  *)
    echo "ERROR Unknown plaform: \"${platform}\""
    ;;
esac

optee_plat="platform=${optee_plat}"

opt_toolpath="toolpath=/toolchains"
export="${out}/export"
seco_export="${out}/export-seco"
ele_export="${out}/export-ele"
ta_export="${export}/export-ta_arm""${arch//[^0-9]/}"
tee_build="../build_arm""${arch//[^0-9]/}"
psaarchtests_src_path="../psa-arch-tests"

for arg in "$@"
do
    case ${arg} in
        toolpath=*)
            opt_toolpath="${arg#*=}"
            check_directory opt_toolpath
            opt_toolpath="toolpath=${opt_toolpath}"
            ;;

        *)
            pr_err "Unknown argument \"${arg}\""
            usage
            ;;
    esac

    shift
done

#
# Build/Prepare external dependencies
#
eval "./scripts/smw_build.sh toolchain ${arch} ${opt_toolpath}"

if [[ ${opt_seco} -eq 1 ]]; then
eval "./scripts/smw_build.sh zlib export=${export}/usr \
       	src=../zlib ${arch} ${opt_toolpath}"
eval "./scripts/smw_build.sh seco export=${seco_export} \
      src=../seco_libs zlib=${export}/usr ${arch} ${opt_toolpath}"
fi

if [[ ${opt_ele} -eq 1 ]]; then
eval "./scripts/smw_build.sh ele export=${ele_export} \
      src=../secure_enclave ${arch} ${opt_toolpath}"
fi

eval "./scripts/smw_build.sh jsonc export=${export} \
      src=../jsonc ${arch} ${opt_toolpath}"
eval "./scripts/smw_build.sh teec export=${export} \
      src=../optee-client out=${tee_build} ${arch} ${opt_toolpath}"
eval "./scripts/smw_build.sh tadevkit export=${ta_export} \
      src=../optee-os out=${tee_build} ${arch} ${optee_plat} ${opt_toolpath}"
eval "./scripts/smw_build.sh psaarchtests src=${psaarchtests_src_path}"

#
# Define common configuration option
#
conf_opts="${arch} ${opt_toolpath}"

# Enable seco/hsm if supported
if [[ ${opt_seco} -eq 1 ]]; then
    conf_opts="${conf_opts} zlib=${export}/usr seco=${seco_export}"
fi

# Enable ELE if supported
if [[ ${opt_ele} -eq 1 ]]; then
    conf_opts="${conf_opts} ele=${ele_export}"
fi


# Enable optee
conf_opts="${conf_opts} teec=${export} tadevkit=${ta_export}"
# Enable tests
conf_opts="${conf_opts} jsonc=${export}"
# Enable PSA Architecture tests
conf_opts="${conf_opts} psaarchtests=${psaarchtests_src_path}"

#
# Configure build targets
#
eval "./scripts/smw_build.sh configure out=${out} ${conf_opts}"
