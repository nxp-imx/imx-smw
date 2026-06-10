define_property(GLOBAL PROPERTY PROP_SUPPORTED_OPERATIONS
        BRIEF_DOCS "Supported Operations" FULL_DOCS "List of supported operations")

include(add_supported_operation)
include(add_target_sources)

add_private_sources(config
        entry.c
        database_operation.c)

if(ENABLE_RNG)
        add_supported_operation(OPERATION_ID_RNG)
endif()

get_filename_component(CMAKE_PARENT_LIST_DIR ${CMAKE_PARENT_LIST_FILE} DIRECTORY)
get_filename_component(CMAKE_PARENT_LIST_DIR ${CMAKE_PARENT_LIST_DIR} DIRECTORY)

add_private_directories(config ${CMAKE_PARENT_LIST_DIR} ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

get_property(LIST_SUPPORTED_OPERATIONS GLOBAL PROPERTY PROP_SUPPORTED_OPERATIONS)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/supported_operations.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/supported_operations.h)
