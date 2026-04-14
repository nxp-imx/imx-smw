if(NOT BUILD_ZEPHYR)
        set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:config> PARENT_SCOPE)

        add_library(config OBJECT "")
        set_target_properties(config PROPERTIES C_VISIBILITY_PRESET hidden)
endif()

include(add_target_sources)

add_private_sources(config
        config.c
        entry.c
        database.c
        keymgr_attr.c)

if(BUILD_STATIC_CONFIG)
        add_subdirectory(static)
else()
        add_subdirectory(dynamic)
endif()

add_private_directories(config ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/subsystems_apis.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/subsystems_apis.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/operations_apis.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/operations_apis.h)
