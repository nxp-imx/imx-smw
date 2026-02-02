if(ENABLE_KEYMGR_MODULE)
    add_operation(GENERATE_KEY)
    add_operation(DERIVE_KEY)
    add_operation(IMPORT_KEY)
    add_operation(EXPORT_KEY)
    add_operation(DELETE_KEY)
    add_operation_implicit(GET_KEY_LENGTHS)
    add_operation_implicit(GET_KEY_ATTRIBUTES)
    add_operation_implicit(COMMIT_KEY_STORAGE)
    add_operation_implicit(KEY_ATTESTATION)
endif()

if(NOT BUILD_ZEPHYR)
    set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:keymgr> PARENT_SCOPE)

    add_library(keymgr OBJECT "")
endif()

include(add_target_sources)

add_private_sources(keymgr keymgr_weak.c)

add_private_sources_ifdef(keymgr ENABLE_KEYMGR_MODULE
    keymgr.c
    keymgr_derive.c
    keymgr_db.c
    keymgr_attest.c
    keymgr_derive_oem_mk.c)

add_private_directories(keymgr ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
