# =============================================================================
# TLS Feature Configuration: 
# - Auto-enables when ELE subsystem (ELE_ROOT) is detected
# - Requires dependencies: ENABLE_KEYMGR_MODULE, ENABLE_SIGN_VERIFY, ENABLE_MAC,
#                          ENABLE_HASH, ENABLE_CIPHER and ENABLE_AEAD
# - User can explicitly override with -DENABLE_TLS=ON/OFF
# - Fails if user requests TLS but dependencies are missing
# - Warns if ELE present but dependencies prevent auto-enable
# =============================================================================

function(enable_tls_option)
    # Check if user explicitly set ENABLE_TLS
    set(USER_SET_TLS FALSE)
    if(DEFINED ENABLE_TLS)
        set(USER_SET_TLS TRUE)
        set(USER_TLS_VALUE ${ENABLE_TLS})
    endif()

    # If not set by user in this run, check if it was set in cache from previous run
    if(NOT USER_SET_TLS)
        get_property(CACHE_TLS_SET CACHE ENABLE_TLS PROPERTY VALUE SET)
        if(CACHE_TLS_SET)
            set(USER_SET_TLS TRUE)
            set(USER_TLS_VALUE ${ENABLE_TLS})
        endif()
    endif()

    # Compute default value based on ELE subsystem
    set(ENABLE_TLS_DEFAULT OFF)
    if(DEFINED ELE_ROOT)
        message(STATUS "TLS defaulting to ON for ELE subsystem")
        set(ENABLE_TLS_DEFAULT ON)
    endif()

    # Check if dependencies are satisfied
    set(TLS_DEPS_OK ON)
    if(ENABLE_KEYMGR_MODULE AND ENABLE_SIGN_VERIFY AND ENABLE_MAC AND ENABLE_HASH  AND ENABLE_CIPHER AND ENABLE_AEAD)
        set(TLS_DEPS_OK ON)
    endif()

    # Determine final ENABLE_TLS value
    if(USER_SET_TLS)
        if(USER_TLS_VALUE)
            if(NOT TLS_DEPS_OK)
                message(FATAL_ERROR
                    "ENABLE_TLS=ON requested, but required dependencies:"
                    "ENABLE_KEYMGR_MODULE or ENABLE_SIGN_VERIFY or ENABLE_MAC\n"
                    "or ENABLE_HASH or ENABLE_CIPHER or ENABLE_AEAD are missing")
            endif()
            # TLS explicitly enabled by user (dependencies satisfied)
            set(ENABLE_TLS ON PARENT_SCOPE)
            message(STATUS "TLS explicitly enabled by user (dependencies satisfied)")
        else()
            # TLS explicitly disabled by user
            set(ENABLE_TLS OFF PARENT_SCOPE)
            message(STATUS "TLS explicitly disabled by user")
        endif()
    else()
        if(ENABLE_TLS_DEFAULT)
            if(TLS_DEPS_OK)
                set(ENABLE_TLS ON PARENT_SCOPE)
                message(STATUS "TLS automatically enabled for ELE subsystem")
            else()
                set(ENABLE_TLS OFF PARENT_SCOPE)
                message(WARNING
                    "Enable TLS for ELE subsystem, but required dependencies\n"
                    "ENABLE_KEYMGR_MODULE or ENABLE_SIGN_VERIFY or ENABLE_MAC\n"
                    "or ENABLE_HASH or ENABLE_CIPHER or ENABLE_AEAD are missing.\n"
                    "Either enable these features or set ENABLE_TLS=OFF")
            endif()
        else()
            # No ELE_ROOT and user didn't request TLS - default to OFF
            set(ENABLE_TLS OFF PARENT_SCOPE)
        endif()
    endif()
endfunction()
