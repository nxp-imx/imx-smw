# Bash completion for nxp_smw CLI tool

# Cache completion data to avoid repeated calls
_nxp_smw_cache_operations=""
_nxp_smw_cache_hash_algos=""
_nxp_smw_cache_lifecycles=""

_nxp_smw_get_operations() {
    if [ -z "$_nxp_smw_cache_operations" ]; then
        # Parse operations from --help output
        _nxp_smw_cache_operations=$(nxp_smw --help 2>/dev/null | \
            grep -E "^\s+[a-z-]+\s+-" | \
            awk '{print $1}' | \
            tr '\n' ' ')

        # Fallback to static list if command fails
        if [ -z "$_nxp_smw_cache_operations" ]; then
            _nxp_smw_cache_operations="rng hash dev-get-uuid dev-get-lifecycle dev-get-attestation"
        fi
    fi
    echo "$_nxp_smw_cache_operations"
}

_nxp_smw_get_hash_algos() {
    if [ -z "$_nxp_smw_cache_hash_algos" ]; then
        # Parse from hash --list output
        # Skip header lines and extract first column (algorithm names)
        _nxp_smw_cache_hash_algos=$(nxp_smw hash --list 2>/dev/null | \
            awk '/^[A-Z]/ && !/^Available/ && !/^Algorithm/ && !/^Note:/ {print $1}' | \
            tr '\n' ' ')

        # Fallback to static list
        if [ -z "$_nxp_smw_cache_hash_algos" ]; then
            _nxp_smw_cache_hash_algos="MD5 SHA1 SHA224 SHA256 SHA384 SHA512 SHA3_224 SHA3_256 SHA3_384 SHA3_512 SM3 SHAKE256"
        fi
    fi
    echo "$_nxp_smw_cache_hash_algos"
}

# Might be useful for set lifecycle
_nxp_smw_get_lifecycles() {
    if [ -z "$_nxp_smw_cache_lifecycles" ]; then
        # Parse from dev-get-lifecycle --list output
        # Skip header lines and extract first column (lifecycle names)
        _nxp_smw_cache_lifecycles=$(nxp_smw dev-get-lifecycle --list 2>/dev/null | \
            awk '/^[A-Z_]/ && !/^Available/ && !/^Lifecycle/ && !/^Note:/ {print $1}' | \
            tr '\n' ' ')

        # Fallback to static list
        if [ -z "$_nxp_smw_cache_lifecycles" ]; then
            _nxp_smw_cache_lifecycles="CURRENT OPEN OEM_OPEN CLOSED OEM_CLOSED CLOSED_LOCKED OEM_LOCKED OEM_RETURN NXP_RETURN"
        fi
    fi
    echo "$_nxp_smw_cache_lifecycles"
}

_nxp_smw_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Get dynamic values
    local operations=$(_nxp_smw_get_operations)
    local hash_algos=$(_nxp_smw_get_hash_algos)
    local lifecycles=$(_nxp_smw_get_lifecycles)

    # Common options
    local common_opts="--help --subsystem --log"

    # If previous word was an option that expects a file, suggest files
    case "${prev}" in
        --output|-o)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --input|-i)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --challenge|-c)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --log|-L)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --subsystem|-S)
            COMPREPLY=( $(compgen -W "ELE TEE SECO" -- ${cur}) )
            return 0
            ;;
        --size|-s)
            COMPREPLY=( $(compgen -W "16 32 64 128 256 512 1024" -- ${cur}) )
            return 0
            ;;
        --algo|-a)
            COMPREPLY=( $(compgen -W "${hash_algos}" -- ${cur}) )
            return 0
            ;;
        --lifecycle|-l)
            COMPREPLY=( $(compgen -W "${lifecycles}" -- ${cur}) )
            return 0
            ;;
    esac

    # If we're completing the first argument (operation)
    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "${operations} --help --version" -- ${cur}) )
        return 0
    fi

    # Get the operation (first argument)
    local operation="${COMP_WORDS[1]}"

    case "${operation}" in
        rng)
            local rng_opts="--size --output --text ${common_opts}"
            COMPREPLY=( $(compgen -W "${rng_opts}" -- ${cur}) )
            ;;
        hash)
            local hash_opts="--algo --input --output --text --length --list ${common_opts}"
            COMPREPLY=( $(compgen -W "${hash_opts}" -- ${cur}) )
            ;;
        dev-get-uuid)
            local devuuid_opts="--output --text ${common_opts}"
            COMPREPLY=( $(compgen -W "${devuuid_opts}" -- ${cur}) )
            ;;
        dev-get-lifecycle)
            local devlife_opts="--output --list ${common_opts}"
            COMPREPLY=( $(compgen -W "${devlife_opts}" -- ${cur}) )
            ;;
        dev-get-attestation)
            local devatt_opts="--output --challenge --text ${common_opts}"
            COMPREPLY=( $(compgen -W "${devatt_opts}" -- ${cur}) )
            ;;
        *)
            COMPREPLY=( $(compgen -W "${common_opts}" -- ${cur}) )
            ;;
    esac
}

complete -F _nxp_smw_completion nxp_smw
