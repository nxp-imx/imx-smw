# Bash completion for nxp_psa CLI tool

# Cache completion data to avoid repeated calls
_nxp_psa_cache_operations=""
_nxp_psa_cache_hash_algos=""
_nxp_psa_cache_key_types=""

# Associative arrays for caching key algorithms by type
declare -A _nxp_psa_cache_key_algos_by_type

# Associative array for caching operation options (requires bash 4+)
declare -A _nxp_psa_cache_op_opts

_nxp_psa_get_operations() {
    if [ -z "$_nxp_psa_cache_operations" ]; then
        # Parse operations from --help output
        _nxp_psa_cache_operations=$(nxp_psa --help 2>/dev/null | \
            grep -E "^\s+[a-z-]+\s+-" | \
            awk '{print $1}' | tr '\n' ' ')

        # Fallback to static list if command fails
        if [ -z "$_nxp_psa_cache_operations" ]; then
            _nxp_psa_cache_operations="rng hash keygen-sym"
        fi
    fi
    echo "$_nxp_psa_cache_operations"
}

_nxp_psa_get_hash_algos() {
    if [ -z "$_nxp_psa_cache_hash_algos" ]; then
        # Parse from hash --list output
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

_nxp_psa_get_key_types() {
    if [ -z "$_nxp_psa_cache_key_types" ]; then
        # Parse from keygen-sym --list output
        # Look for the "Key Types:" line and extract the comma-separated values
        _nxp_psa_cache_key_types=$(nxp_psa keygen-sym --list 2>/dev/null | \
            grep "^Key Types:" | \
            sed 's/^Key Types:[[:space:]]*//' | \
            tr ',' '\n' | \
            sed 's/^[[:space:]]*//' | \
            sed 's/[[:space:]]*$//' | \
            tr '\n' ' ')

        # Fallback to static list
        if [ -z "$_nxp_psa_cache_key_types" ]; then
            _nxp_psa_cache_key_types="AES ARIA CAMELLIA CHACHA20 XCHACHA20 DES HMAC"
        fi
    fi
    echo "$_nxp_psa_cache_key_types"
}

_nxp_psa_get_key_algos_for_type() {
    local key_type="$1"

    if [ -z "$key_type" ]; then
        return 1
    fi

    # Convert to uppercase for consistency
    key_type=$(echo "$key_type" | tr '[:lower:]' '[:upper:]')

    # Check cache first
    if [ -n "${_nxp_psa_cache_key_algos_by_type[$key_type]}" ]; then
        echo "${_nxp_psa_cache_key_algos_by_type[$key_type]}"
        return 0
    fi

    # Parse algorithms for this specific key type from keygen-sym --list
    local algos=""

    # Try to extract from --list output
    # Look for the key type in either Cipher or AEAD sections
    algos=$(nxp_psa keygen-sym --list 2>/dev/null | \
        awk -v type="$key_type" '
        BEGIN {
            in_section = 0;
            found = 0
        }
        # Start of Cipher section
        /^Cipher / {
            in_section = 1;
            section = "cipher";
            next
        }
        # Start of AEAD section
        /^AEAD / {
            in_section = 2;
            section = "aead";
            next
        }
        # Start of MAC section
        /^MAC / {
            in_section = 3;
            section = "mac";
            next
        }
        # End of section (empty line or new section)
        /^[A-Z]/ && in_section > 0 && !/Key types:/ && !/Modes:/ && !/Hash:/ {
            in_section = 0
        }
        # Check if key type is in this section
        in_section > 0 && /Key types:/ {
            if ($0 ~ type) {
                found = in_section
            }
        }
        # Extract modes/hash for the matched section
        found > 0 && /Modes:/ {
            sub(/.*Modes:[[:space:]]*/, "")
            print $0
            found = 0
        }
        found == 3 && /Hash:/ {
            sub(/.*Hash:[[:space:]]*/, "")
            print $0
            found = 0
        }
        ' | \
        tr ', ' '\n ' | \
        sed 's/^[[:space:]]*//' | \
        sed 's/[[:space:]]*$//' | \
        grep -v '^$' | \
        sort -u | \
        tr '\n' ' ')

    # Fallback to static lists based on key type
    if [ -z "$algos" ]; then
        case "$key_type" in
            AES)
                algos="CBC CBC-PKCS7 CFB CTR ECB OFB XTS CCM GCM"
                ;;
            ARIA)
                algos="CBC CBC-PKCS7 CFB CTR ECB OFB CCM GCM"
                ;;
            CAMELLIA)
                algos="CBC CBC-PKCS7 CFB CTR ECB OFB CCM GCM"
                ;;
            CHACHA20)
                algos="STREAM-CIPHER POLY1305"
                ;;
            XCHACHA20)
                algos="STREAM-CIPHER POLY1305"
                ;;
            DES)
                algos="CBC CBC-PKCS7 ECB"
                ;;
            HMAC)
                algos="MD5 SHA1 SHA224 SHA256 SHA384 SHA512 SHA3-224 SHA3-256 SHA3-384 SHA3-512 SM3"
                ;;
            *)
                algos=""
                ;;
        esac
    fi

    # Cache the result
    _nxp_psa_cache_key_algos_by_type[$key_type]="$algos"
    echo "$algos"
}

_nxp_psa_get_operation_opts() {
    local operation="$1"

    # Check cache first
    if [ -n "${_nxp_psa_cache_op_opts[$operation]}" ]; then
        echo "${_nxp_psa_cache_op_opts[$operation]}"
        return 0
    fi

    # Parse options from operation help output (long options only)
    local opts=$(nxp_psa "$operation" --help 2>/dev/null | \
        grep -oE '(^|[[:space:]])--?[a-z][a-z0-9-]*' | \
        sed 's/^[[:space:]]*//' | grep '^--' | sort -u | \
        tr '\n' ' ')

    # Cache the result
    if [ -n "$opts" ]; then
        _nxp_psa_cache_op_opts[$operation]="$opts"
        echo "$opts"
    else
        # Fallback for common options if parsing fails
        echo "--help --subsystem --log"
    fi
}

_nxp_psa_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Get dynamic values
    local operations=$(_nxp_psa_get_operations)
    local hash_algos=$(_nxp_psa_get_hash_algos)
    local key_types=$(_nxp_psa_get_key_types)

    # If previous word was an option that expects a value,
    # provide context-specific completion
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
            # Context-aware size completion
            local operation="${COMP_WORDS[1]}"
            if [ "$operation" = "keygen-sym" ]; then
                COMPREPLY=( $(compgen -W "56 112 128 168 192 256 384 512" -- ${cur}) )
            else
                COMPREPLY=( $(compgen -W "16 32 64 128 256 512 1024" -- ${cur}) )
            fi
            return 0
            ;;
        --algo|-a)
            local operation="${COMP_WORDS[1]}"
            if [ "$operation" = "hash" ]; then
                COMPREPLY=( $(compgen -W "${hash_algos}" -- ${cur}) )
            elif [ "$operation" = "keygen-sym" ]; then
                # Find the key type from the command line
                local key_type=""
                local i
                for ((i = 2; i < ${#COMP_WORDS[@]}; i++)); do
                    if [[ "${COMP_WORDS[i]}" == "-t" || "${COMP_WORDS[i]}" == "--type" ]]; then
                        if [ $((i + 1)) -lt ${#COMP_WORDS[@]} ]; then
                            key_type="${COMP_WORDS[i+1]}"
                            break
                        fi
                    fi
                done

                # If we found a key type, get algorithms for that specific type
                if [ -n "$key_type" ]; then
                    local key_algos=$(_nxp_psa_get_key_algos_for_type "$key_type")
                    COMPREPLY=( $(compgen -W "${key_algos}" -- ${cur}) )
                else
                    # No key type specified yet, offer all possible algorithms
                    COMPREPLY=( $(compgen -W "CBC CTR ECB GCM CCM POLY1305 MD5 SHA1 SHA256 SHA384 SHA512" -- ${cur}) )
                fi
            fi
            return 0
            ;;
        --type|-t)
            COMPREPLY=( $(compgen -W "${key_types}" -- ${cur}) )
            return 0
            ;;
        --usage|-u)
            COMPREPLY=( $(compgen -W "encrypt decrypt sign verify" -- ${cur}) )
            return 0
            ;;
        --id)
            # Numeric ID - no completion
            return 0
            ;;
        --length)
            # Hash length - numeric value, no completion
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

    # Special handling for flags that don't take arguments
    case "${cur}" in
        --transient|--non-sensitive|--list)
            COMPREPLY=( $(compgen -W "${cur}" -- ${cur}) )
            return 0
            ;;
    esac

    # Get operation-specific options dynamically
    local operation_opts=$(_nxp_psa_get_operation_opts "$operation")
    COMPREPLY=( $(compgen -W "${operation_opts}" -- ${cur}) )
}

complete -F _nxp_psa_completion nxp_psa
