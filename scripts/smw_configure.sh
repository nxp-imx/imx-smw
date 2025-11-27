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
    all modules and setting up the external dependencies.
    Let build type as default Release type.

    CAUTION: We assume this script is executed from the SMW top level
    source code directory where the output build directory <dir>
    will be created.

    $(basename "$0") <dir> <arch> <subsystem> [OPTIONS]
    ═══════════════════════════════════════════════════════════════
    Mandatory Parameters:
    ═══════════════════════════════════════════════════════════════
      <dir>          : Output build directory
      <arch>         : Architecture aarch32 or aarch64
      <subsystem>    : Subsystem combination (comma-separated list without spaces)
       Options:
          tee            : TEE Only
          seco           : SECO Only
          ele            : ELE Only
          tee,seco       : SECO + TEE
          tee,ele        : ELE + TEE
          coverity       : Coverity analysis

      Optional Configuration:
      toolpath=<dir> : Toolchain installation path
                       Default: /toolchains

EOF
    exit 1
}

if [[ $# -lt 3 ]]; then
    usage
fi

out=$1
arch="arch=$2"
subsystems="$3"
shift 3

#
# Convert platform to optee platform
#
optee_plat=
opt_tee=0
opt_seco=0
opt_ele=0
opt_tls=0
subsystem=

if [[ "${subsystems}" == "coverity" ]]; then
    opt_tee=1

    if [[ ${arch} =~ "aarch32" ]]; then
        optee_plat="imx-mx7dsabresd"
    else
        opt_seco=1
        opt_ele=1
        optee_plat="imx-mx93evk"
    fi
else
    # Split subsystems by comma and process each
    IFS=',' read -ra SUBSYS_ARRAY <<< "${subsystems}"

    for subsystem in "${SUBSYS_ARRAY[@]}"; do
        case ${subsystem} in
            tee)
                opt_tee=1
                ;;
            seco)
                opt_seco=1
                ;;
            ele)
                opt_ele=1
                opt_tls=1
                ;;
            *)
                echo "ERROR: Unknown subsystem: \"${subsystem}\""
                usage
                ;;
        esac
    done

    # Validate at least one subsystem is enabled
    if [[ ${opt_tee} -eq 0 && ${opt_seco} -eq 0 && ${opt_ele} -eq 0 ]]; then
        echo "ERROR: At least one subsystem must be specified"
        usage
    fi

    # Set OPTEE platform based on subsystem combination
    if [[ ${opt_tee} -eq 1 ]]; then
        if [[ ${opt_ele} -eq 1 ]]; then
            # TEE + ELE combination
            optee_plat="imx-mx95evk"
        elif [[ ${opt_seco} -eq 1 ]]; then
            # TEE + SECO combination
            optee_plat="imx-mx8qxpmek"
        else
            # TEE only
            if [[ ${arch} =~ "aarch32" ]]; then
                optee_plat="imx-mx7dsabresd"
            else
                optee_plat="imx-mx8mmevk"
            fi
        fi
    fi
fi

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
    eval "./scripts/smw_build.sh seco export=${seco_export} \
        src=../secure_enclave ${arch} ${opt_toolpath}"
fi

if [[ ${opt_ele} -eq 1 ]]; then
    eval "./scripts/smw_build.sh ele export=${ele_export} \
        src=../secure_enclave ${arch} ${opt_toolpath}"
fi

eval "./scripts/smw_build.sh jsonc export=${export} \
      src=../jsonc ${arch} ${opt_toolpath}"
eval "./scripts/smw_build.sh libsqlite export=${export}/usr \
      src=../libsqlite ${arch} ${opt_toolpath}"

if [[ ${opt_tee} -eq 1 ]]; then
    eval "./scripts/smw_build.sh libuuid_config export=${export}/usr \
          src=../libuuid ${arch} ${opt_toolpath}"
    eval "./scripts/smw_build.sh teec export=${export} \
          src=../optee-client libuuid_config=${export}/usr out=${tee_build} ${arch} ${opt_toolpath}"
    eval "./scripts/smw_build.sh tadevkit export=${ta_export} \
          src=../optee-os out=${tee_build} ${arch} ${optee_plat} ${opt_toolpath}"
fi

eval "./scripts/smw_build.sh psaarchtests src=${psaarchtests_src_path}"

#
# Define common configuration option
#
conf_opts="${arch} ${opt_toolpath}"

# Enable SECO if supported
if [[ ${opt_seco} -eq 1 ]]; then
    conf_opts="${conf_opts} seco=${seco_export}"
fi

# Enable ELE if supported
if [[ ${opt_ele} -eq 1 ]]; then
    conf_opts="${conf_opts} ele=${ele_export}"
fi

# Enable TLS features if supported
if [[ ${opt_tls} -eq 1 ]]; then
    conf_opts="${conf_opts} tls"
fi

# Enable optee if supported
if [[ ${opt_tee} -eq 1 ]]; then
    conf_opts="${conf_opts} libuuid_config=${export}/usr teec=${export} tadevkit=${ta_export}"
fi

# Enable tests
conf_opts="${conf_opts} jsonc=${export}"
# Enable PSA Architecture tests
conf_opts="${conf_opts} psaarchtests=${psaarchtests_src_path}"
# Enable SQLite
conf_opts="${conf_opts} libsqlite=${export}/usr"

#
# Configure build targets
#
eval "./scripts/smw_build.sh configure out=${out} ${conf_opts}"
