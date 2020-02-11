cmake_minimum_required(VERSION 3.5)

project(SecurityMiddlewareLibrary C)

set(BUILD_SHARED_LIBS ON)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DENABLE_DEBUG")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
endif()
set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(OS linux)

set(output_directory ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${output_directory})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${output_directory})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${output_directory})

set(SMW_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/inc)
set(INCLUDE_DIR ${INCLUDE_DIR} ${SMW_INCLUDE_DIR})

add_subdirectory(osal)
add_subdirectory(core)

add_library(smw ${OBJ_LIST} ${INCLUDE_DIR})
target_include_directories(smw PUBLIC ${INCLUDE_DIR})

install(TARGETS smw DESTINATION bin)

