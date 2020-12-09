#!/bin/bash
set -eE
trap 'error ${LINENO}' ERR

script_name=$0
script_full=$(realpath "${script_name}")
script_dir=$(dirname "${script_full}")

function toolchain()
{
    cmd_script="cmake -DFORCE_TOOLCHAIN_INSTALL=True ${opt_toolpath} ${opt_toolname}"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install toolchain %s \n" "${opt_arch}"
    printf "***************************************\n"
    printf "\033[0m\n"

    cmd_script="${cmd_script} -P ${toolchain_script}"
    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function zlib()
{
    cmd_script="cmake ${opt_toolchain}"
    zlib_script="${script_dir}/build_zlib.cmake"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install zlib to %s \n" "${opt_export}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} ]]; then
        usage_zlib
        exit 1
    fi

    if [[ ! -z ${opt_src} ]]; then
        cmd_script="${cmd_script} -DZLIB_SRC_PATH=${opt_src}"
    fi

    cmd_script="${cmd_script} -DZLIB_ROOT=${opt_export} -P ${zlib_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function seco()
{
    cmd_script="cmake ${opt_toolchain} ${opt_zlib}"
    seco_script="${script_dir}/build_seco.cmake"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install SECO to %s \n" "${opt_export}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} || -z ${opt_src} ]]; then
        usage_seco
        exit 1
    fi

    cmd_script="${cmd_script} -DSECO_SRC_PATH=${opt_src} -DSECO_ROOT=${opt_export} -P ${seco_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function teec()
{
    cmd_script="cmake ${opt_toolchain} ${opt_builddir}"
    teec_script="${script_dir}/build_teec.cmake"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install OPTEE Client to %s \n" "${opt_export}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} || -z ${opt_src} ]]; then
        usage_teec
        exit 1
    fi

    cmd_script="${cmd_script} -DTEEC_SRC_PATH=${opt_src} -DTEEC_ROOT=${opt_export} -P ${teec_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function tadevkit()
{
    cmd_script="cmake ${opt_toolchain} ${opt_platform} ${opt_builddir}"
    tadevkit_script="${script_dir}/build_tadevkit.cmake"

    printf "\033[0;32m\n"
    printf "***************************************************\n"
    printf " Install OPTEE TA Development Kit to %s \n" "${opt_export}"
    printf "***************************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} || -z ${opt_src} ]]; then
        usage_tadevkit
        exit 1
    fi

    cmd_script="${cmd_script} -DOPTEE_OS_SRC_PATH=${opt_src} -DTA_DEV_KIT_ROOT=${opt_export} -P ${tadevkit_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function smw()
{
    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Build SMW to %s \n" "${opt_out}"
    printf "***************************************\n"
    printf "\033[0m\n"

    cmd_script="cmake .. ${opt_toolchain}"
    cmd_script="${cmd_script} ${opt_buildtype} ${opt_verbose}"
    cmd_script="${cmd_script} ${opt_zlib} ${opt_seco}"
    cmd_script="${cmd_script} ${opt_teec} ${opt_tadevkit}"
    cmd_script="${cmd_script} ${opt_test} ${opt_jsonc}"

    mkdir -p "${opt_out}"
    cd "${opt_out}"
    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
    eval "make"
    if ${opt_package}; then
        package_name="libsmw_package.tar.gz"
        tmp_install_dir="tmp_install"

        mkdir -p "${tmp_install_dir}"
        eval "make install DESTDIR=${tmp_install_dir} > /dev/null"
        eval "cp -P ../${opt_jsonc_lib}/libjson-c.so.* ${tmp_install_dir}/usr/lib/."
        eval "cd ${tmp_install_dir} && tar -czf ../${package_name} . && cd .."
        rm -rf "${tmp_install_dir}"
    fi
}

function jsonc()
{
    cmd_script="cmake ${opt_toolchain}"
    jsonc_script="${script_dir}/build_jsonc.cmake"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install json-c to %s \n" "${opt_export}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} || -z ${opt_src} ]]; then
        usage_jsonc
        exit 1
    fi

    cmd_script="${cmd_script} -DJSONC_SRC_PATH=${opt_src} -DJSONC_ROOT=${opt_export} -P ${jsonc_script}"

    if [[ ${opt_version} && ${opt_hash} ]]; then
        cmd_script="${cmd_script} -DJSONC_VERSION=${opt_version} -DJSONC_HASH=${opt_hash}"
    fi

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function usage_toolchain()
{
    printf "\n"
    printf "To install the toolchain aarch32 or aarch64\n"
    printf "  %s toolchain arch=[arch] toolpath=[dir] toolname=[name]\n" "${script_name}"
    printf "    arch     = Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_zlib()
{
    printf "\n"
    printf "To build and install the ZLIB Library\n"
    printf "  %s zlib export=[dir] src=[dir] arch=[arch] toolpath=[dir] toolname=[name]\n" "${script_name}"
    printf "    export   = Export directory\n"
    printf "    src      = [optional] Temporary directory where install sources\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_seco()
{
    printf "\n"
    printf "To build and install the SECO libraries\n"
    printf "  %s seco export=[dir] src=[dir] zlib=[root] arch=[arch] toolpath=[dir] toolname=[name]\n" "${script_name}"
    printf "    export   = Export directory\n"
    printf "    src      = Source directory\n"
    printf "    zlib     = [optional] ZLIB library root directory\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_teec()
{
    printf "\n"
    printf "To build and install the OPTEE Client libraries\n"
    printf "  %s teec export=[dir] src=[dir] out=[dir] arch=[arch] toolpath=[dir] toolname=[name]\n" "${script_name}"
    printf "    export   = Export directory\n"
    printf "    src      = Source directory\n"
    printf "    out      = [optional] Build root directory\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_tadevkit()
{
    printf "\n"
    printf "To build and install the OPTEE TA Development Kit\n"
    printf "  %s tadevkit export=[dir] src=[dir] out=[dir] platform=[platforn] arch=[arch] toolpath=[dir] toolname=[name]\n" "${script_name}"
    printf "    export   = Export directory\n"
    printf "    src      = Source directory\n"
    printf "    out      = [optional] Build root directory\n"
    printf "    platform = [optional] OPTEE OS Platform (default=mx8qmmek)\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_smw()
{
    printf "\n"
    printf "To build the Secure Middleware\n"
    printf " - Note: all dependencies must be present\n"
    printf "  %s smw out=[dir] debug package verbose=[lvl] zlib=[dir] seco=[dir] teec=[dir] tadevkit=[dir] arch=[arch] toolpath=[dir] toolname=[name]\n" "${script_name}"
    printf "    out      = Build directory\n"
    printf "    debug    = [optional] if set build type to debug\n"
    printf "    package  = [optional] if set build package\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "  To enable HSM subsystem [optional]\n"
    printf "    zlib     = ZLIB library root directory\n"
    printf "    seco     = SECO export directory\n"
    printf "  To enable TEE subsystem [optional]\n"
    printf "    teec     = OPTEE Client export directory\n"
    printf "    tadevkit = OPTEE TA Development Kit export directory\n"
    printf "  To enable tests [optionnal]\n"
    printf "    test\n"
    printf "    jsonc = JSON-C export directory\n"
    printf "\n"
}

function usage_jsonc()
{
    printf "\n"
    printf "To build and install the JSON-C Library\n"
    printf "  %s jsonc export=[dir] src=[dir] arch=[arch] toolpath=[dir] toolname=[name]\n" "${script_name}"
    printf "    export   = Export directory\n"
    printf "    src      = Temporary directory where install sources\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "    version  = [optional] JSON-C Version to upload\n"
    printf "    hash     = [optional] JSON-C Hash of archive to upload\n"
    printf "\n"
}

function usage()
{
    printf "\n"
    printf "*******************************************\n"
    printf " Usage of Security Middleware build script \n"
    printf "*******************************************\n"
    usage_toolchain
    usage_zlib
    usage_seco
    usage_teec
    usage_tadevkit
    usage_jsonc
    usage_smw
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

opt_action=$1
opt_package=false
shift

for arg in "$@"
do
    case $arg in
        arch=*)
            opt_arch="${arg#*=}"
            toolchain_script="${script_dir}/${opt_arch}_toolchain.cmake"
            if [[ ! -e "$toolchain_script" ]]; then
                printf "Unknown toolchain %s \n" "${opt_arch}"
                usage
                exit 1
            fi

            opt_toolscript="-DCMAKE_TOOLCHAIN_FILE=${toolchain_script}"
            ;;

        toolpath=*)
            opt_toolpath="${arg#*=}"
            opt_toolpath="-DTOOLCHAIN_PATH=${opt_toolpath}"
            ;;

        toolname=*)
            opt_toolname="${arg#*=}"
            opt_toolname="-DTOOLCHAIN_NAME=${opt_toolname}"
            ;;

        export=*)
            opt_export="${arg#*=}"
            ;;

        src=*)
            opt_src="${arg#*=}"
            ;;

        zlib=*)
            opt_zlib="${arg#*=}"
            opt_zlib="-DZLIB_ROOT=${opt_zlib}"
            ;;

        platform=*)
            opt_platform="${arg#*=}"
            opt_platform="-DPLATFORM=${opt_platform}"
            ;;

        out=*)
            opt_out="${arg#*=}"
            opt_builddir="-DBUILD_DIR=${opt_out}"
            ;;

        seco=*)
            opt_seco="${arg#*=}"
            opt_seco="-DSECO_ROOT=${opt_seco}"
            ;;

        teec=*)
            opt_teec="${arg#*=}"
            opt_teec="-DTEEC_ROOT=${opt_teec}"
            ;;

        tadevkit=*)
             opt_tadevkit="${arg#*=}"
             opt_tadevkit="-DTA_DEV_KIT_ROOT=${opt_tadevkit}"
             ;;

        debug)
             opt_buildtype="-DCMAKE_BUILD_TYPE=Debug"
             ;;

        package)
             opt_package=true
             ;;

        verbose=*)
             opt_verbose="${arg#*=}"
             opt_verbose="-DVERBOSE=${opt_verbose}"
             ;;

        test)
             opt_test="-DBUILD_TEST=ON"
             ;;

        jsonc=*)
             opt_jsonc="${arg#*=}"
             opt_jsonc_lib="${opt_jsonc}/usr/lib"
             opt_jsonc="-DJSONC_ROOT=${opt_jsonc}"
             ;;

        version=*)
             opt_version="${arg#*=}"
             ;;

        hash=*)
             opt_hash="${arg#*=}"
             ;;

        *)
            usage
            exit 1
            ;;
    esac

    shift
done

opt_toolchain="${opt_toolname} ${opt_toolpath} ${opt_toolscript}"

case $opt_action in
    toolchain)
        toolchain
        ;;

    zlib)
        zlib
        ;;

    seco)
        seco
        ;;

    teec)
        teec
        ;;

    tadevkit)
        tadevkit
        ;;

    smw)
        smw
        ;;

    jsonc)
        jsonc
        ;;

    *)
        usage
        ;;
esac


