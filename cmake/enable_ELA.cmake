# =============================================================================
# ELA Feature Configuration: 
# - Only enables when user explicitly sets -DENABLE_ELA=ON
# - Requires ELE subsystem (ELE_ROOT) to be defined
# - Requires ENABLE_KEYMGR_MODULE and at least one of: ENABLE_CIPHER,
#   ENABLE_AEAD or ENABLE_MAC
# - Fails if user requests ELA but dependencies are missing or ELE is disabled
# =============================================================================

function(enable_ela_option)
    set(USER_SET_ELA FALSE)
    if(DEFINED ENABLE_ELA)
        set(USER_SET_ELA TRUE)
        set(USER_ELA_VALUE ${ENABLE_ELA})
    endif()

    if(NOT USER_SET_ELA)
        get_property(CACHE_ELA_SET CACHE ENABLE_ELA PROPERTY VALUE SET)
        if(CACHE_ELA_SET)
            set(USER_SET_ELA TRUE)
            set(USER_ELA_VALUE ${ENABLE_ELA})
        endif()
    endif()

    set(ELA_DEPS_OK OFF)
    if(ENABLE_KEYMGR_MODULE AND (ENABLE_CIPHER OR ENABLE_MAC OR ENABLE_AEAD))
        set(ELA_DEPS_OK ON)
    endif()

    if(USER_SET_ELA AND USER_ELA_VALUE)
        if(NOT DEFINED ELE_ROOT)
            message(FATAL_ERROR
                "ENABLE_ELA=ON requested, but ELE subsystem is not enabled.\n"
                "ELE_ROOT must be defined to use ELA.")
        endif()

        if(NOT ELA_DEPS_OK)
            message(FATAL_ERROR
                "ENABLE_ELA=ON requires the following dependencies to be enabled:\n"
                "  - ENABLE_KEYMGR_MODULE\n"
                "  - At least one of: ENABLE_CIPHER or ENABLE_AEAD or ENABLE_MAC\n")
        endif()

        set(ENABLE_ELA ON PARENT_SCOPE)
        message(STATUS "ELA explicitly enabled by user (all requirements satisfied)")
    else()
        set(ENABLE_ELA OFF PARENT_SCOPE)
    endif()
endfunction()
