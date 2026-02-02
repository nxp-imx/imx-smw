if(NOT BUILD_ZEPHYR)
        set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:psa> PARENT_SCOPE)

        add_library(psa OBJECT "")
        set_target_properties(psa PROPERTIES C_VISIBILITY_PRESET hidden)
endif()

include(add_target_sources)

add_private_sources(psa
        asn1.c
        common.c
        crypto.c
        initial_attestation.c
        internal_trusted_storage.c
        protected_storage.c
        keymgr.c
        util_status.c)
add_private_directories(psa ${INCLUDE_DIR})
