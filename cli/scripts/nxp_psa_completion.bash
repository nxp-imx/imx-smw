# Bash completion for nxp_psa CLI tool

# Cache completion data to avoid repeated calls
_nxp_psa_cache_operations=""
_nxp_psa_cache_hash_algos=""
_nxp_psa_cache_key_types_sym=""
_nxp_psa_cache_key_types_asym=""

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
            _nxp_psa_cache_operations="rng hash keygen-sym keygen-asym"
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

_nxp_psa_get_key_types_sym() {
    if [ -z "$_nxp_psa_cache_key_types_sym" ]; then
        # Parse from keygen-sym --list output
        # Look for the "Key Types:" line and extract the comma-separated values
        _nxp_psa_cache_key_types_sym=$(nxp_psa keygen-sym --list 2>/dev/null | \
            grep "^Key Types:" | \
            sed 's/^Key Types:[[:space:]]*//' | \
            tr ',' '\n' | \
            sed 's/^[[:space:]]*//' | \
            sed 's/[[:space:]]*$//' | \
            tr '\n' ' ')

        # Fallback to static list
        if [ -z "$_nxp_psa_cache_key_types_sym" ]; then
            _nxp_psa_cache_key_types_sym="AES ARIA CAMELLIA CHACHA20 XCHACHA20 DES HMAC"
        fi
    fi
    echo "$_nxp_psa_cache_key_types_sym"
}

_nxp_psa_get_key_types_asym() {
    if [ -z "$_nxp_psa_cache_key_types_asym" ]; then
        # Parse from keygen-asym --list output
        _nxp_psa_cache_key_types_asym=$(nxp_psa keygen-asym --list 2>/dev/null | \
            grep "^Key Types:" | \
            sed 's/^Key Types:[[:space:]]*//' | \
            tr ',' '\n' | \
            sed 's/^[[:space:]]*//' | \
            sed 's/[[:space:]]*$//' | \
            tr '\n' ' ')

        # Fallback to static list
        if [ -z "$_nxp_psa_cache_key_types_asym" ]; then
            _nxp_psa_cache_key_types_asym="RSA SECP_R1 SECP_K1 BRAINPOOL_P_R1 MONTGOMERY TWISTED_EDWARDS ED25519 ED448 X25519 X448"
        fi
    fi
    echo "$_nxp_psa_cache_key_types_asym"
}

_nxp_psa_get_asym_algos_for_type() {
    local key_type="$1"

    if [ -z "$key_type" ]; then
        return 1
    fi

    # Convert to uppercase for consistency
    key_type=$(echo "$key_type" | tr '[:lower:]' '[:upper:]')

    # Return algorithms based on key type
    case "$key_type" in
        RSA)
            # Check usage flags to determine if sign or encrypt
            local usage=""
            local i
            for ((i = 2; i < ${#COMP_WORDS[@]}; i++)); do
                if [[ "${COMP_WORDS[i]}" == "-u" || "${COMP_WORDS[i]}" == "--usage" ]]; then
                    if [ $((i + 1)) -lt ${#COMP_WORDS[@]} ]; then
                        usage="${COMP_WORDS[i+1]}"
                        break
                    fi
                fi
            done

            if [[ "$usage" == *"encrypt"* || "$usage" == *"decrypt"* ]]; then
                echo "OAEP-SHA256 OAEP-SHA384 OAEP-SHA512 PKCS1V15-CRYPT"
            else
                echo "PSS-SHA256 PSS-SHA384 PSS-SHA512 PKCS1V15-SHA256 PKCS1V15-SHA384 PKCS1V15-SHA512"
            fi
            ;;
        SECP_R1|SECP_K1|BRAINPOOL_P_R1)
            echo "ECDSA-SHA256 ECDSA-SHA384 ECDSA-SHA512 ECDH"
            ;;
        ED25519|ED448|TWISTED_EDWARDS)
            echo "EDDSA-PURE EDDSA-PREHASHED"
            ;;
        X25519|X448|MONTGOMERY)
            echo "ECDH"
            ;;
        *)
            echo ""
            ;;
    esac
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

    # Determine which operation we're working with
    local operation="${COMP_WORDS[1]}"

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
            if [ "$operation" = "keygen-sym" ]; then
                COMPREPLY=( $(compgen -W "56 112 128 168 192 256 384 512" -- ${cur}) )
            elif [ "$operation" = "keygen-asym" ]; then
                # Find the key type to suggest appropriate sizes
                local key_type=""
                local i
                for ((i = 2; i < ${#COMP_WORDS[@]}; i++)); do
                    if [[ "${COMP_WORDS[i]}" == "-t" || "${COMP_WORDS[i]}" == "--type" ]]; then
                        if [ $((i + 1)) -lt ${#COMP_WORDS[@]} ]; then
                            key_type=$(echo "${COMP_WORDS[i+1]}" | tr '[:lower:]' '[:upper:]')
                            break
                        fi
                    fi
                done

                case "$key_type" in
                    RSA)
                        COMPREPLY=( $(compgen -W "1024 2048 3072 4096" -- ${cur}) )
                        ;;
                    SECP_R1|SECP_K1|BRAINPOOL_P_R1)
                        COMPREPLY=( $(compgen -W "192 224 256 384 521" -- ${cur}) )
                        ;;
                    MONTGOMERY|TWISTED_EDWARDS)
                        COMPREPLY=( $(compgen -W "255 448" -- ${cur}) )
                        ;;
                    ED25519|X25519)
                        COMPREPLY=( $(compgen -W "255" -- ${cur}) )
                        ;;
                    ED448|X448)
                        COMPREPLY=( $(compgen -W "448" -- ${cur}) )
                        ;;
                    *)
                        COMPREPLY=( $(compgen -W "256 384 521 2048 4096" -- ${cur}) )
                        ;;
                esac
            else
                COMPREPLY=( $(compgen -W "16 32 64 128 256 512 1024" -- ${cur}) )
            fi
            return 0
            ;;
        --algo|-a)
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
            elif [ "$operation" = "keygen-asym" ]; then
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

                # Get algorithms for asymmetric key type
                if [ -n "$key_type" ]; then
                    local asym_algos=$(_nxp_psa_get_asym_algos_for_type "$key_type")
                    COMPREPLY=( $(compgen -W "${asym_algos}" -- ${cur}) )
                else
                    # No key type specified yet, show common asymmetric algorithms
                    COMPREPLY=( $(compgen -W "ECDSA-SHA256 PSS-SHA256 EDDSA-PURE ECDH OAEP-SHA256" -- ${cur}) )
                fi
            fi
            return 0
            ;;
        --type|-t)
            if [ "$operation" = "keygen-sym" ]; then
                local key_types=$(_nxp_psa_get_key_types_sym)
                COMPREPLY=( $(compgen -W "${key_types}" -- ${cur}) )
            elif [ "$operation" = "keygen-asym" ]; then
                local key_types=$(_nxp_psa_get_key_types_asym)
                COMPREPLY=( $(compgen -W "${key_types}" -- ${cur}) )
            fi
            return 0
            ;;
        --usage|-u)
            if [ "$operation" = "keygen-asym" ]; then
                COMPREPLY=( $(compgen -W "sign verify encrypt decrypt derive export" -- ${cur}) )
            else
                COMPREPLY=( $(compgen -W "encrypt decrypt sign verify" -- ${cur}) )
            fi
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
