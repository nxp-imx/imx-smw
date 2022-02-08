#
# Check PSA Architecture Tests repo is present or fetch it
#
if(NOT DEFINED PSA_ARCH_TESTS_SRC_PATH)
    message(FATAL_ERROR
            "-DPSA_ARCH_TESTS_SRC_PATH="
            "<PSA Architecture Tests source path> missing")
endif()

if(NOT IS_ABSOLUTE ${PSA_ARCH_TESTS_SRC_PATH})
    set(PSA_ARCH_TESTS_SRC_PATH
        "${CMAKE_SOURCE_DIR}/${PSA_ARCH_TESTS_SRC_PATH}")
endif()

if (EXISTS ${PSA_ARCH_TESTS_SRC_PATH})
    message(STATUS "PSA Architecture Tests repo already fetched")
    return()
endif()

set(PSA_ARCH_TESTS psa-arch-tests)
set(PSA_ARCH_TESTS_URL https://github.com/ARM-software/psa-arch-tests.git)
set(PSA_ARCH_TESTS_BRANCH main)
set(PSA_ARCH_TESTS_REV 2a1852252a9b9af655cbe02d5d3c930952d0d798)

find_package(Git REQUIRED)

file(MAKE_DIRECTORY ${PSA_ARCH_TESTS_SRC_PATH})
execute_process(COMMAND ${GIT_EXECUTABLE} clone --branch ${PSA_ARCH_TESTS_BRANCH} --progress ${PSA_ARCH_TESTS_URL} ${PSA_ARCH_TESTS_SRC_PATH}
                WORKING_DIRECTORY ${PSA_ARCH_TESTS_SRC_PATH}/..
                TIMEOUT 300
                RESULT_VARIABLE RES)
if(NOT ${RES} EQUAL 0)
    message(FATAL_ERROR "Git clone ${PSA_ARCH_TESTS_URL} failed: ${RES}")
endif()

execute_process(COMMAND ${GIT_EXECUTABLE} checkout ${PSA_ARCH_TESTS_REV}
                WORKING_DIRECTORY ${PSA_ARCH_TESTS_SRC_PATH}
                TIMEOUT 300
                RESULT_VARIABLE RES)
if(NOT ${RES} EQUAL 0)
    message(FATAL_ERROR "Git checkout ${PSA_ARCH_TESTS_REV} failed: ${RES}")
endif()

