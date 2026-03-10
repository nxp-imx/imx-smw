#!/bin/bash
set -eu

#
# Single source for all SMW feature options and configs
#

#
# Feature options definitions
# In future, to add a new future option, add an entry in the SMW_FEATURE_OPTIONS
# array below.
#
declare -a SMW_FEATURE_OPTIONS=(
    # Functional features
    "enable_keymgr_module|Key manager module"
    "enable_hash|Hash operations"
    "enable_sign_verify|Signature operations"
    "enable_mac|MAC operations"
    "enable_cipher|Cipher operations"
    "enable_aead|AEAD operations"
    "enable_asymmetric_encryption|Asymmetric encryption"
    "enable_storage_module|Storage module"
    "enable_object_module|Object module"
    "enable_devmgr_module|Device manager module"
    "enable_device_attestation|Device attestation"
    "enable_device_lifecycle|Device lifecycle"
    "enable_device_reprovision|Device reprovision"
    "enable_rng|Random number generation"
    "enable_tls|TLS support"
    # Build/development features
    "enable_code_coverage|Enable code coverage support"
    "enable_psa_default_alt|Enable the support of an alternative subsystem for the PSA interface operations."
)

#
# Config: Configs are predefined feature combinations for various build scenarios.
# Each config explicitly enables specific features; unlisted features are
# automatically disabled.

# To add a new config, create an array named CONFIG_<NAME> and list all the
# feature options to be enabled and update get_config_descriptions() function
# with config details.
#
# Naming convention:
#   - Array name: CONFIG_<NAME> (uppercase, underscores)
#   - Usage: config=<name> (lowercase, hyphens)
#   - Example: config=code-coverage → CONFIG_CODE_COVERAGE
#
# Example:
# Enable code coverage support with basic crypto operations:
#   declare -a CONFIG_CODE_COVERAGE=(
#       "enable_code_coverage=on"
#       "enable_rng=on"
#       "enable_hash=on"
#   )
#
# Usage: ./smw_configure.sh build aarch64 tee config=code-coverage
#

# config: crypto-basic
# Basic cryptographic operations
declare -a CONFIG_CRYPTO_BASIC=(
    "enable_hash=on"
    "enable_rng=on"
)

# config: crypto-symmetric
# Symmetric cryptography
declare -a CONFIG_CRYPTO_SYMMETRIC=(
    "enable_keymgr_module=on"
    "enable_object_module=on"
    "enable_mac=on"
    "enable_cipher=on"
    "enable_aead=on"
)

# config: crypto-asymmetric
# Asymmetric cryptography
declare -a CONFIG_CRYPTO_ASYMMETRIC=(
    "enable_hash=on"
    "enable_keymgr_module=on"
    "enable_object_module=on"
    "enable_sign_verify=on"
    "enable_asymmetric_encryption=on"
)

# config: crypto-full-no-tls
# Complete cryptographic operations without TLS
declare -a CONFIG_CRYPTO_FULL_NO_TLS=(
    "enable_hash=on"
    "enable_rng=on"
    "enable_keymgr_module=on"
    "enable_object_module=on"
    "enable_mac=on"
    "enable_cipher=on"
    "enable_aead=on"
    "enable_sign_verify=on"
    "enable_asymmetric_encryption=on"
)

# config: crypto-full-tls
# Complete cryptographic operations with TLS support
declare -a CONFIG_CRYPTO_FULL_TLS=(
    "enable_hash=on"
    "enable_rng=on"
    "enable_keymgr_module=on"
    "enable_object_module=on"
    "enable_mac=on"
    "enable_cipher=on"
    "enable_aead=on"
    "enable_sign_verify=on"
    "enable_asymmetric_encryption=on"
    "enable_tls=on"
)

# config: secure-device
# Device management and lifecycle
declare -a CONFIG_SECURE_DEVICE=(
    "enable_devmgr_module=on"
    "enable_device_attestation=on"
    "enable_device_reprovision=on"
    "enable_device_lifecycle=on"
)

# config: all
# Enable all functional features
declare -a CONFIG_ALL=(
    "enable_hash=on"
    "enable_rng=on"
    "enable_keymgr_module=on"
    "enable_object_module=on"
    "enable_mac=on"
    "enable_cipher=on"
    "enable_aead=on"
    "enable_sign_verify=on"
    "enable_asymmetric_encryption=on"
    "enable_storage_module=on"
    "enable_devmgr_module=on"
    "enable_device_attestation=on"
    "enable_device_lifecycle=on"
    "enable_device_reprovision=on"
    "enable_tls=on"
)

# config: all-no-tls
# All functional features except TLS
declare -a CONFIG_ALL_NO_TLS=(
    "enable_hash=on"
    "enable_rng=on"
    "enable_keymgr_module=on"
    "enable_object_module=on"
    "enable_mac=on"
    "enable_cipher=on"
    "enable_aead=on"
    "enable_sign_verify=on"
    "enable_asymmetric_encryption=on"
    "enable_storage_module=on"
    "enable_devmgr_module=on"
    "enable_device_attestation=on"
    "enable_device_lifecycle=on"
    "enable_device_reprovision=on"
)

function pr_err()
{
    printf "\033[1;31m\n"
    printf "%s" "$@"
    printf "\033[0m\n"
}

#
# Validate if a feature option is valid
# Args: $1 = option name (e.g., "enable_keymgr_module")
#       $2 = option value (e.g., "on" or "off")
#
function validate_feature_option()
{
    local option_name="$1"
    local option_value="$2"

    # Validate option name exists
    local option_found=0
    for entry in "${SMW_FEATURE_OPTIONS[@]}"; do
        local valid_option="${entry%%|*}"
        if [[ "${option_name}" == "${valid_option}" ]]; then
            option_found=1
            break
        fi
    done

    if [[ ${option_found} -eq 0 ]]; then
        pr_err "ERROR: Invalid feature option: \"${option_name}\"\n"
        get_feature_options_usage >&2
        return 1
    fi

    # Validate option value is on or off
    if [[ "${option_value}" != "on" && "${option_value}" != "off" ]]; then
        pr_err "ERROR: Invalid value \"${option_value}\" for option \"${option_name}\". Must be on or off.\n"
        return 1
    fi

    return 0
}

#
# Validate if a config name is valid
# Args: $1 = config name (e.g., "crypto-basic")
#
function validate_config()
{
    local config_name="$1"

    # Convert config name to variable name
    # "crypto-basic" → "CONFIG_CRYPTO_BASIC"
    local config_var="CONFIG_${config_name^^}"
    config_var="${config_var//-/_}"

    # Check if config array already exists
    if ! declare -p "${config_var}" &>/dev/null; then
        pr_err "ERROR: Unknown config: \"${config_name}\"\n"
        get_config_descriptions >&2
        return 1
    fi

    return 0
}

#
# Convert a single feature option to CMake format
# Args: $1 = feature option (e.g., "enable_hash=on")
# Output: CMake flag (e.g., "-DENABLE_HASH=ON")
#
function convert_feature_to_cmake_flag()
{
    local feature="$1"
    local option_name="${feature%%=*}"
    local option_value="${feature#*=}"

    # Convert to CMake format: enable_xxx=on -> -DENABLE_XXX=ON
    option_name="${option_name^^}"
    option_value="${option_value^^}"
    echo "-D${option_name}=${option_value}"
}

#
# Apply config configuration and output CMake flags
# Args: $1 = config name (e.g., "crypto-basic")
# Output: Space-separated CMake flags
#
function convert_config_to_cmake_flag()
{
    local config="$1"
    local flags=""

    # Convert config name (CRYPTO_BASIC) to variable name (CONFIG_CRYPTO_BASIC)
    local config_var="CONFIG_${config^^}"
    config_var="${config_var//-/_}"

    # Get reference to corresponding config array
    local -n config_array="${config_var}"

    # Build map of explicitly set features
    declare -A set_features
    for option in "${config_array[@]}"; do
        local option_name="${option%%=*}"
        set_features["${option_name}"]=1
        flags="${flags} $(convert_feature_to_cmake_flag "${option}")"
    done

    # Auto-disable features not listed in config
    for entry in "${SMW_FEATURE_OPTIONS[@]}"; do
        local feature_name="${entry%%|*}"
        if [[ "${set_features[${feature_name}]:-0}" != "1" ]]; then
            flags="${flags} $(convert_feature_to_cmake_flag "${feature_name}=off")"
        fi
    done

    echo "${flags}"
}

function get_feature_options_usage()
{
    printf " Options:\n"

    for entry in "${SMW_FEATURE_OPTIONS[@]}"; do
        local option="${entry%%|*}"
        local description="${entry#*|}"
        printf "    %-38s : %s\n" "${option}=<on|off>" "${description}"
    done
}

function get_config_descriptions()
{
    cat << 'EOF'
    config=<name> : Selects which SMW feature set to build.
     Options:
        crypto-basic        : Basic crypto operations (hash, RNG)
        crypto-symmetric   : Symmetric crypto operations (keymgr, object, MAC, cipher, AEAD)
        crypto-asymmetric  : Asymmetric crypto operations (keymgr, object, sign/verify, asymmetric encryption, hash)
        crypto-full-no-tls : All crypto operations except TLS support (crypto-basic, crypto-symmetric, crypto-asymmetric)
        crypto-full-tls    : All crypto operations - (crypto-basic, crypto-symmetric, crypto-asymmetric, TLS)
        secure-device      : Device management and lifecycle (devmgr, attestation, reprovision, lifecycle)
        all-no-tls         : All features except TLS support (crypto-full-no-tls, secure-storage, secure-device)
        all                : Enable all features (crypto-full-tls, secure-storage, secure-device)

    Note: Individual features can be overridden using enable_*=<on|off>
EOF
}