set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:config> PARENT_SCOPE)

add_library(config OBJECT config.c ${INCLUDE_DIR})
target_include_directories(config PRIVATE ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/subsystems_apis.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/subsystems_apis.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/operations_apis.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/operations_apis.h)
