cmake_minimum_required(VERSION 3.5)

project(SecurityMiddlewareLibrary C)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

if(VERBOSE)
    if(NOT VERBOSE MATCHES "^[0-9]$")
        message(FATAL_ERROR "VERBOSE must be an integer")
    endif()
    if(NOT VERBOSE EQUAL 0)
        add_definitions(-DENABLE_TRACE)
    endif()
    if(${VERBOSE} GREATER 4)
        set(VERBOSE 4)
    endif()
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(${VERBOSE} GREATER 2)
            set(VERBOSE 2)
        endif()
    endif()
    add_definitions(-DTRACE_LEVEL=${VERBOSE})
    message(STATUS TRACE_LEVEL: ${VERBOSE})
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DENABLE_DEBUG)
endif()

if(SECO_LIBS_EXPORT_DIR)
    if(NOT IS_ABSOLUTE ${SECO_LIBS_EXPORT_DIR})
        set(SECO_LIBS_EXPORT_DIR "${CMAKE_SOURCE_DIR}/${SECO_LIBS_EXPORT_DIR}")
    endif()
    set(ENABLE_HSM ON)
endif()

set(BUILD_SHARED_LIBS ON)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wall -Werror)
endif()
set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(OS linux)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/public ${CMAKE_SOURCE_DIR}/inc)

add_subdirectory(osal)
add_subdirectory(core)

add_library(smw ${OBJ_LIST} ${INCLUDE_DIR})
target_include_directories(smw PRIVATE ${INCLUDE_DIR})
target_include_directories(smw INTERFACE "$<INSTALL_INTERFACE:include>")

FIND_PACKAGE(Threads REQUIRED)

target_link_libraries(smw PUBLIC ${SMW_LIBS} ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS smw DESTINATION lib)
install(FILES public/smw_status.h DESTINATION include)
