#!/bin/bash
set -e

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

    $(basename "$0") <dir> <arch> <platform>
      <dir>      : Mandatory output build directory
      <arch>     : Mandatory architecture aarch32 or aarch64
      <platform> : Mandatory i.MX platform name

EOF
    exit 1
}

if [[ $# -lt 3 ]]; then
    usage
fi

out=$1
arch="arch=$2"
platform="$3"

#
# Convert platform to optee platform
#
optee_plat=
opt_seco=0
case ${platform} in
    imx8qxpc0mek)
        optee_plat="mx8qxpmek"
	opt_seco=1
	;;

    imx8mmevk)
        optee_plat="mx8mmevk"
	;;

    imx7dsabresd)
        optee_plat="mx7dsabresd"
	;;

    *)
	echo "ERROR Unknown plaform: \"${platform}\""
        ;;
esac

optee_plat="platform=${optee_plat}"

toolpath="toolpath=/opt/toolchains"
export="./export"
ta_export="${export}/export-ta_arm""${arch//[^0-9]/}"

#
# Build/Prepare external dependencies
#
eval "./scripts/smw_build.sh toolchain ${arch} ${toolpath}"

if [[ ${opt_seco} -eq 1 ]]; then
eval "./scripts/smw_build.sh zlib export=${export}/usr \
       	src=../zlib ${arch} ${toolpath}"
eval "./scripts/smw_build.sh seco export=${export} \
      src=../seco_libs zlib=${export}/usr ${arch} ${toolpath}"
fi

eval "./scripts/smw_build.sh jsonc export=${export} \
      src=../jsonc ${arch} ${toolpath}"
eval "./scripts/smw_build.sh teec export=${export} \
      src=../optee-client out=../build ${arch} ${toolpath}"
eval "./scripts/smw_build.sh tadevkit export=${ta_export} \
      src=../optee-os out=../build ${arch} ${optee_plat} ${toolpath}"

#
# Tools required to build documentation
#
eval "./scripts/smw_build.sh sphinx"
eval "./scripts/smw_build.sh linuxdoc"

#
# Define common configuration option
#
conf_opts="${arch} ${toolpath}"

# Enable seco/hsm if supported
if [[ ${opt_seco} -eq 1 ]]; then
    conf_opts="${conf_opts} zlib=${export}/usr seco=${export}"
fi

# Enable optee
conf_opts="${conf_opts} teec=${export} tadevkit=${ta_export}"
# Enable tests
conf_opts="${conf_opts} jsonc=${export}"

# Set documentations format to HTML
conf_opts="${conf_opts} format=\"html\""

#
# Configure build targets
#
eval "./scripts/smw_build.sh configure out=${out} ${conf_opts}"
