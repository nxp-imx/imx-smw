cmake_minimum_required(VERSION 3.12)

project(SecurityMiddleware VERSION 2.4 LANGUAGES C)

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

option(CODE_COVERAGE "Enable Code Coverage analysis" OFF)

if(CODE_COVERAGE)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(FATAL_ERROR "Code coverage required build type \"Debug\"")
    endif()

    message(STATUS "Code Coverage enabled, force all traces ON")
    set(VERBOSE 4)
endif()

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_INSTALL_PREFIX /usr)
include(GNUInstallDirs)

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
cmake_dependent_option(ENABLE_CIPHER "Enable Cipher" ON "ENABLE_KEYMGR_MODULE" OFF)
cmake_dependent_option(ENABLE_MAC "Enable MAC" ON "ENABLE_KEYMGR_MODULE" OFF)
option(ENABLE_RNG "Enable Random number generator" ON)
option(ENABLE_TLS12 "Enable TLS 1.2 features" OFF)

option(ENABLE_PSA_DEFAULT_ALT "Enable alternative subsystem selection for PSA API" OFF)

option(ENABLE_DEVMGR_MODULE "Enable device manager module" ON)
cmake_dependent_option(ENABLE_DEVICE_ATTESTATION "Enable device attestation" ON "ENABLE_DEVMGR_MODULE" OFF)

#
# Define all targets compiler options
#
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wall -Wextra -Werror)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

#
# Define tests build and install targets
# Building SMW and/or PKCS11 tests with make command
# "make build_tests"
#
# Installing SMW and/PKCS11 tests with make command
# "make install_tests [DESTDIR=dir]"
#
add_custom_target(build_tests)
add_custom_target(install_tests)

# Include OS Abstration layer
set(OS linux)
add_subdirectory(osal/${OS})

# Include SMW Library (using osal)
add_subdirectory(core)

# Include SMW Library tests
add_subdirectory(tests)

# Include PKCS#11 project
add_subdirectory(pkcs11)

# Include SMW Documentations
add_subdirectory(Documentations)

if(NOT DISABLE_CMAKE_CONFIG)
    # Create the SMW Package configuration
    include(CMakePackageConfigHelpers)

    configure_package_config_file(cmake/NXP_SMWConfig.cmake.in
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/NXP_SMWConfig.cmake
        INSTALL_DESTINATION cmake)

    write_basic_package_version_file(
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/NXP_SMWConfigVersion.cmake
        COMPATIBILITY SameMajorVersion)

    install(FILES ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/NXP_SMWConfig.cmake
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/NXP_SMWConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake)

    export(EXPORT SMWTargets
        NAMESPACE NXP_SMW::
        FILE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cmake/NXP_SMWTargets.cmake")

    install(EXPORT SMWTargets
        NAMESPACE NXP_SMW::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake"
        FILE "NXP_SMWTargets.cmake")

    install(FILES ${CMAKE_SOURCE_DIR}/cmake/FindSeco.cmake
                  ${CMAKE_SOURCE_DIR}/cmake/FindEle.cmake
                  ${CMAKE_SOURCE_DIR}/cmake/FindTeec.cmake
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake")
endif()
