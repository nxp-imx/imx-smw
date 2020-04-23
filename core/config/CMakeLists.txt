set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:config> PARENT_SCOPE)

add_library(config OBJECT "" ${INCLUDE_DIR})
target_sources(config PRIVATE
               entry.c
               parser.c
               database.c
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c>)
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND VERBOSE AND NOT VERBOSE EQUAL 0)
target_sources(config PRIVATE
               database_debug.c
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr_debug.c>)
endif()
target_include_directories(config PRIVATE ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/subsystems_apis.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/subsystems_apis.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/operations_apis.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/operations_apis.h)
