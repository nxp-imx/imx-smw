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

    $(basename "$0") <dir> <arch>
      <dir>  : Mandatory output build directory
      <arch> : Mandatory architecture aarch32 or aarch64

EOF
    exit 1
}

if [[ $# -ne 2 ]]; then
    usage
fi

out=$1
arch="arch=$2"

toolpath="toolpath=/opt/toolchains"
export="./export"

#
# Build/Prepare external dependencies
#
eval "./scripts/smw_build.sh toolchain ${arch} ${toolpath}"
eval "./scripts/smw_build.sh zlib export=${export}/usr \
       	src=../zlib ${arch} ${toolpath}"
eval "./scripts/smw_build.sh jsonc export=${export} \
      src=../jsonc ${arch} ${toolpath}"
eval "./scripts/smw_build.sh seco export=${export} \
      src=../seco_libs zlib=${export}/usr ${arch} ${toolpath}"
eval "./scripts/smw_build.sh teec export=${export} \
      src=../optee-client out=../build ${arch} ${toolpath}"
eval "./scripts/smw_build.sh tadevkit export=${export}/export-ta_arm64 \
      src=../optee-os out=../build ${arch} ${toolpath}"

#
# Define common configuration option
#
conf_opts="${arch} ${toolpath}"
# Enable seco/hsm
conf_opts="${conf_opts} zlib=${export}/usr seco=${export}"
# Enable optee
conf_opts="${conf_opts} teec=${export} tadevkit=${export}/export-ta_arm64"
# Enable tests
conf_opts="${conf_opts} jsonc=${export}"

#
# Configure build targets
#
eval "./scripts/smw_build.sh configure out=${out} ${conf_opts}"
