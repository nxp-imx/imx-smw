# Bash completion for nxp_psa CLI tool

# Cache completion data to avoid repeated calls
_nxp_psa_cache_operations=""
_nxp_psa_cache_hash_algos=""

_nxp_psa_get_operations() {
    if [ -z "$_nxp_psa_cache_operations" ]; then
        # Parse operations from --help output
        _nxp_psa_cache_operations=$(nxp_psa --help 2>/dev/null | \
            grep -E "^\s+[a-z-]+\s+-" | \
            awk '{print $1}' | \
            tr '\n' ' ')

        # Fallback to static list if command fails
        # Note: Device operations (dev-*) are not supported in PSA
        if [ -z "$_nxp_psa_cache_operations" ]; then
            _nxp_psa_cache_operations="rng hash"
        fi
    fi
    echo "$_nxp_psa_cache_operations"
}

_nxp_psa_get_hash_algos() {
    if [ -z "$_nxp_psa_cache_hash_algos" ]; then
        # Parse from hash --list output
        # Skip header lines and extract first column (algorithm names)
        _nxp_psa_cache_hash_algos=$(nxp_psa hash --list 2>/dev/null | \
            awk '/^[A-Z]/ && !/^Available/ && !/^Algorithm/ && !/^Note:/ {print $1}' | \
            tr '\n' ' ')

        # Fallback to static list
        if [ -z "$_nxp_psa_cache_hash_algos" ]; then
            _nxp_psa_cache_hash_algos="MD5 SHA1 SHA224 SHA256 SHA384 SHA512 SHA3_224 SHA3_256 SHA3_384 SHA3_512 SM3 SHAKE256"
        fi
    fi
    echo "$_nxp_psa_cache_hash_algos"
}

_nxp_psa_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Get dynamic values
    local operations=$(_nxp_psa_get_operations)
    local hash_algos=$(_nxp_psa_get_hash_algos)

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
        *)
            COMPREPLY=( $(compgen -W "${common_opts}" -- ${cur}) )
            ;;
    esac
}

complete -F _nxp_psa_completion nxp_psa