#!/bin/bash
set -eu

# Source feature options definitions
script_dir="$(dirname "$(realpath "$0")")"
source "${script_dir}/smw_feature_options.sh"

function check_directory()
{
    declare -n mydir=$1
    mydir="${mydir/\~/$HOME}"

    if [[ ! -d "${mydir}" ]]; then
        pr_err "${mydir} is not a directory"
    fi
}

function pr_err()
{
    printf "\033[1;31m\n"
    printf "%s" "$@"
    printf "\033[0m\n"
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
          doc            : Documentation Only

    ═══════════════════════════════════════════════════════════════
    Optional Configuration Parameters: [OPTIONS]
    ═══════════════════════════════════════════════════════════════
      toolpath=<path> : Toolchain installation path
                       Default: /toolchains
      debug          : Build in Debug mode instead of Release

$(get_config_descriptions | sed 's/^/  /')

      Feature Options: Can override config settings
$(get_feature_options_usage | sed 's/^/      /')

    ═══════════════════════════════════════════════════════════════
    Examples:
    ═══════════════════════════════════════════════════════════════
      # Basic configuration with single subsystem
      $(basename "$0") build aarch64 tee

      # Multiple subsystems with custom toolchain path
      $(basename "$0") build aarch64 tee,ele toolpath=/opt/toolchains

      # ELE with ELA enabled
      $(basename "$0") build aarch64 ele enable_ela=on

      # Multiple subsystems with crypto-basic config
      $(basename "$0") build aarch64 tee,seco config=crypto-basic

      # Custom feature configuration
      $(basename "$0") build aarch64 tee,ele \\
          config=crypto-basic \\
          enable_keymgr_module=on \\
          enable_sign_verify=on

      # All features except AEAD and cipher support
      $(basename "$0") build aarch64 tee,ele \\
          toolpath=/opt/toolchains \\
          config=all \\
          enable_aead=off \\
          enable_cipher=off

      # Custom debug build with AEAD, key manager and  code coverage enabled
      $(basename "$0") build aarch64 tee,ele \\
          enable_keymgr_module=on \\
          enable_aead=on \\
          enable_code_coverage=on \\
          debug

      # Coverity analysis
      $(basename "$0") build aarch64 coverity

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
opt_tss2=0
opt_doc_only=0

opt_ela_enable=0

if [[ "${subsystems}" == "coverity" ]]; then
    opt_tee=1

    if [[ ${arch} =~ "aarch32" ]]; then
        optee_plat="imx-mx7dsabresd"
    else
        # For aarch64, enable all subsystems for maximum coverage
        opt_seco=1
        opt_ele=1
        opt_tss2=1
        opt_ela_enable=1
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
                opt_tss2=1
                ;;
            doc)
                opt_doc_only=1
                ;;
            *)
                echo "ERROR: Unknown subsystem: \"${subsystem}\""
                usage
                ;;
        esac
    done

    # Validate at least one subsystem is enabled
    if [[ ${opt_tee} -eq 0 && ${opt_seco} -eq 0 && ${opt_ele} -eq 0 && ${opt_doc_only} -eq 0 ]]; then
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
opt_config=""
opt_feature_options=""
opt_debug=0

for arg in "$@"
do
    case ${arg} in
        toolpath=*)
            opt_toolpath="${arg#*=}"
            check_directory opt_toolpath
            opt_toolpath="toolpath=${opt_toolpath}"
            ;;

        config=*)
            config_value="${arg#*=}"

            if validate_config "${config_value}"; then
                opt_config="${arg}"
            else
                exit 1
            fi
            ;;

        enable_ela=*)
            # Extract option value
            option_name="${arg%%=*}"
            option_value="${arg#*=}"

            # Track enable_ela separately for ELE build step
            if validate_feature_option "${option_name}" "${option_value}"; then
                if [[ "${option_value}" == "on" ]]; then
                    opt_ela_enable=1
                fi

                opt_feature_options="${opt_feature_options} ${arg}"
            else
                exit 1
            fi
            ;;

        enable_*=*)
            # Extract option name and validate
            option_name="${arg%%=*}"
            option_value="${arg#*=}"

            if validate_feature_option "${option_name}" "${option_value}"; then
                opt_feature_options="${opt_feature_options} ${arg}"
            else
                exit 1
            fi
            ;;

        debug)
            opt_debug=1
        ;;

        *)
            pr_err "Unknown argument \"${arg}\""
            usage
            ;;
    esac

    shift
done

#
# For coverity scans, enable all possible build options to maximize the code coverage
# for scan analysis. This ensures all code paths are analyzed.
# For coverity scans, append required options after arg parsing.
# Appended last so they take precedence over any user-supplied flags.
# - enable_psa_default_alt=on for all coverity scans (aarch32 and aarch64)
# - enable_ela=on for aarch64 coverity scan only (ELA not supported on aarch32)
#
if [[ "${subsystems}" == "coverity" ]]; then
    opt_feature_options="${opt_feature_options} enable_psa_default_alt=on"

    if [[ ! ${arch} =~ "aarch32" ]]; then
        opt_feature_options="${opt_feature_options} enable_ela=on"
    fi
fi

if [[ ${opt_doc_only} -eq 1 ]]; then
    eval "./scripts/smw_build.sh configure out=${out} doc_only"
    exit 0
fi

#
# enable_ela requires ELE subsystem
#
if [[ ${opt_ela_enable} -eq 1 && ${opt_ele} -eq 0 ]]; then
    pr_err "enable_ela=on requires ELE subsystem to be enabled"
    exit 1
fi

#
# Build/Prepare external dependencies
#
eval "./scripts/smw_build.sh toolchain ${arch} ${opt_toolpath}"

#
# Define common configuration option
#
conf_opts="${arch} ${opt_toolpath}"

# Enable SECO if supported
if [[ ${opt_seco} -eq 1 ]]; then
    eval "./scripts/smw_build.sh seco export=${seco_export} \
        src=../secure_enclave ${arch} ${opt_toolpath}"

    conf_opts="${conf_opts} seco=${seco_export}"
fi

# Enable ELE if supported
if [[ ${opt_ele} -eq 1 ]]; then
    ela_opt="enable_ela=off"
    if [[ ${opt_ela_enable} -eq 1 ]]; then
        ela_opt="enable_ela=on"
    fi

    eval "./scripts/smw_build.sh ele export=${ele_export} \
        src=../secure_enclave ${arch} ${opt_toolpath} ${ela_opt}"

    conf_opts="${conf_opts} ele=${ele_export}"
fi

# Enable TSS2 if supported
if [[ ${opt_tss2} -eq 1 ]]; then
    eval "./scripts/smw_build.sh libtss2 export=${export}/usr \
          src=../libtss2 ${arch} ${opt_toolpath}"

    conf_opts="${conf_opts} libtss2=${export}/usr"
fi

eval "./scripts/smw_build.sh jsonc export=${export} \
      src=../jsonc ${arch} ${opt_toolpath}"

# Enable tests
conf_opts="${conf_opts} jsonc=${export}"

eval "./scripts/smw_build.sh libsqlite export=${export}/usr \
      src=../libsqlite ${arch} ${opt_toolpath}"

# Enable SQLite
conf_opts="${conf_opts} libsqlite=${export}/usr"

# Enable optee if supported
if [[ ${opt_tee} -eq 1 ]]; then
    eval "./scripts/smw_build.sh libuuid_config export=${export}/usr \
          src=../libuuid ${arch} ${opt_toolpath}"
    eval "./scripts/smw_build.sh teec export=${export} \
          src=../optee-client libuuid_config=${export}/usr out=${tee_build} ${arch} ${opt_toolpath}"
    eval "./scripts/smw_build.sh tadevkit export=${ta_export} \
          src=../optee-os out=${tee_build} ${arch} ${optee_plat} ${opt_toolpath}"

    conf_opts="${conf_opts} libuuid_config=${export}/usr teec=${export} tadevkit=${ta_export}"
fi

eval "./scripts/smw_build.sh psaarchtests src=${psaarchtests_src_path}"

# Enable PSA Architecture tests
conf_opts="${conf_opts} psaarchtests=${psaarchtests_src_path}"

# Add config option to configuration (applied first)
if [[ -n ${opt_config} ]]; then
    conf_opts="${conf_opts} ${opt_config}"
fi

# Add feature options to configuration (applied after config to override)
if [[ -n ${opt_feature_options} ]]; then
    conf_opts="${conf_opts} ${opt_feature_options}"
fi

# Enable debug build if requested
if [[ ${opt_debug} -eq 1 ]]; then
    conf_opts="${conf_opts} debug"
fi

#
# Configure build targets
#
eval "./scripts/smw_build.sh configure out=${out} ${conf_opts}"
