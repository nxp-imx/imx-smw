if(ENABLE_STORAGE_MODULE OR ENABLE_KEYMGR_MODULE)
    add_operation_implicit(IS_OBJECT_PRESENT)
endif()

if(NOT BUILD_ZEPHYR)
    set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:utils> PARENT_SCOPE)

    add_library(utils OBJECT "")
    set_target_properties(utils PROPERTIES C_VISIBILITY_PRESET hidden)
endif()

include(add_target_sources)

add_private_sources(utils
    aead.c
    attrs.c
    base64.c
    cipher.c
    endian.c
    exec.c
    hash.c
    info.c
    list.c
    key.c
    mac.c
    math.c
    name.c
    object_db.c
    object_query.c
    operation_context.c
    sign_verify.c)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND VERBOSE AND NOT VERBOSE EQUAL 0)
    add_private_sources(utils list_debug.c)
endif()

add_private_directories(utils ${INCLUDE_DIR})
