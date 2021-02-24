cmake_minimum_required(VERSION 3.5)

project(SecurityMiddleware VERSION 0.1 LANGUAGES C)

include(CMakeDependentOption)

# Configuration types
if(NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "Configs" FORCE)
endif()
if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Set default build type Release.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
else()
    message(STATUS "Build type ${CMAKE_BUILD_TYPE}.")
endif()

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_INSTALL_PREFIX /usr)

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
else()
    set(VERBOSE 0)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DENABLE_DEBUG)
endif()

option(ENABLE_KEYMGR_MODULE "Link the Key manager" ON)
cmake_dependent_option(ENABLE_HASH "Enable Hash" ON "ENABLE_KEYMGR_MODULE" OFF)
cmake_dependent_option(ENABLE_SIGN_VERIFY "Enable Sign and Verify" ON "ENABLE_KEYMGR_MODULE" OFF)
cmake_dependent_option(ENABLE_HMAC "Enable HMAC" ON "ENABLE_KEYMGR_MODULE" OFF)

#
# Define all targets compiler options
#
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wall -Werror)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Include OS Abstration layer
set(OS linux)
add_subdirectory(osal)

# Include SMW Library (using osal)
add_subdirectory(core)

# Include SMW Library tests
add_subdirectory(tests)

# Include PKCS#11 project
add_subdirectory(pkcs11)
