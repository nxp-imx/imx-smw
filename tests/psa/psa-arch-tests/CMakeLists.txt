cmake_minimum_required(VERSION 3.5)

include(ExternalProject)

# Build PSA testsuite
message(STATUS "Build PSA crypto testsuite")

if(NOT DEFINED PSA_ARCH_TESTS_SRC_PATH)
    message(FATAL_ERROR
            "-DPSA_ARCH_TESTS_SRC_PATH="
            "<PSA Architecture Tests source path> missing")
endif()

if(NOT IS_ABSOLUTE ${PSA_ARCH_TESTS_SRC_PATH})
    set(PSA_ARCH_TESTS_SRC_PATH
        "${CMAKE_SOURCE_DIR}/${PSA_ARCH_TESTS_SRC_PATH}")
endif()

set(PSA_ARCH_TESTS psa-arch-tests)
set(PSA_ARCH_TESTS ${PSA_ARCH_TESTS} PARENT_SCOPE)
set(PSA_SOURCE_DIR ${PSA_ARCH_TESTS_SRC_PATH})
set(PSA_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(PSA_ARCH_TESTS_SUITE CRYPTO)
string(TOLOWER ${PSA_ARCH_TESTS_SUITE} PSA_ARCH_TESTS_API_DIR)
set(PSA_ARCH_TESTS_TARGET tgt_dev_apis_linux)

message(STATUS "Add external project ${PSA_ARCH_TESTS}")
ExternalProject_Add(${PSA_ARCH_TESTS}
    SOURCE_DIR ${PSA_SOURCE_DIR}
    SOURCE_SUBDIR api-tests
    BINARY_DIR ${PSA_BUILD_DIR}
    PATCH_COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/${PSA_ARCH_TESTS_API_DIR}/testsuite.db ${PSA_SOURCE_DIR}/api-tests/dev_apis/${PSA_ARCH_TESTS_API_DIR}/testsuite.db
    CMAKE_ARGS -DTARGET=${PSA_ARCH_TESTS_TARGET} -DSUITE=${PSA_ARCH_TESTS_SUITE} -DPSA_INCLUDE_PATHS=${CMAKE_SOURCE_DIR}/public -DTOOLCHAIN=GCC_LINUX -DCOMPILER_NAME=${CMAKE_C_COMPILER} -Wno-dev
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${PSA_BUILD_DIR}/val/val_nspe.a
    BUILD_BYPRODUCTS ${PSA_BUILD_DIR}/platform/pal_nspe.a
    BUILD_BYPRODUCTS ${PSA_BUILD_DIR}/dev_apis/${PSA_ARCH_TESTS_API_DIR}/test_combine.a
    EXCLUDE_FROM_ALL TRUE
    )

set(PSA_LIBS
    ${PSA_BUILD_DIR}/val/val_nspe.a
    ${PSA_BUILD_DIR}/platform/pal_nspe.a
    ${PSA_BUILD_DIR}/dev_apis/${PSA_ARCH_TESTS_API_DIR}/test_combine.a
    PARENT_SCOPE)

