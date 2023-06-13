cmake_minimum_required(VERSION 3.12)

project(smwtest VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

if(NOT DEFINED JSONC_ROOT)
    message(STATUS "Tests not enabled, JSONC_ROOT not defined")
    return()
endif()

find_package(Jsonc REQUIRED)

enable_testing()

set(SMW_TESTS_TARGET_DATA_DIR share/smw/tests)
set(SMW_CTEST_TEST_FILE_DIR ${SMW_TESTS_TARGET_DATA_DIR})
set(DEFAULT_OUT_STATUS_DIR ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_DATA_DIR})
set(SMW_TESTS_TARGET_SCRIPTS_DIR ${SMW_TESTS_TARGET_DATA_DIR}/scripts)
set(SMW_TESTS_TARGET_DEF_DIR ${SMW_TESTS_TARGET_DATA_DIR}/test_definition)
set(SMW_TESTS_TARGET_DEF_DIR_FULL_PATH ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_DEF_DIR})
set(SMW_TESTS_TARGET_CONFIG_DIR ${SMW_TESTS_TARGET_DATA_DIR}/config)
set(SMW_TESTS_TARGET_PSA_DIR ${SMW_TESTS_TARGET_DATA_DIR}/psa)

set(TEST_DEF_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test_definition)
set(SMW_CONFIG_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/config)

set(TEST_BIN_INC ${CMAKE_CURRENT_BINARY_DIR}/engine/inc)
set(TEST_SRC_INC ${CMAKE_CURRENT_SOURCE_DIR}/engine/inc)
set(TEST_SCRIPTS_SRC ${CMAKE_CURRENT_SOURCE_DIR}/scripts)
set(TEST_SCRIPTS_BIN ${CMAKE_CURRENT_BINARY_DIR}/scripts)

message(STATUS "Tests enabled")
message(STATUS "    JSON C Library: ${JSONC_LIBRARY}")
message(STATUS "    JSON C Include dir: ${JSONC_INCLUDE_DIR}")

set(TEST_CMD ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_SCRIPTS_DIR}/run_simple_test.sh)

configure_file(${TEST_SRC_INC}/paths.h.in ${TEST_BIN_INC}/paths.h)
configure_file(${TEST_SCRIPTS_SRC}/run_simple_test.sh.in
               ${TEST_SCRIPTS_BIN}/run_simple_test.sh @ONLY)

add_executable(${PROJECT_NAME}
               EXCLUDE_FROM_ALL
               engine/run_app.c
               engine/run_thread.c
               engine/test_engine.c)

target_include_directories(${PROJECT_NAME} PRIVATE
                           ${TEST_SRC_INC}
                           ${TEST_BIN_INC}
                           ${JSONC_INCLUDE_DIR}
                           ${CMAKE_SOURCE_DIR}/inc)

add_subdirectory(engine/utils)
add_subdirectory(engine/psa)
add_subdirectory(engine/smw)

target_link_libraries(${PROJECT_NAME} PRIVATE ${JSONC_LIBRARY})
target_link_libraries(${PROJECT_NAME} PRIVATE pthread rt)
target_link_libraries(${PROJECT_NAME} PRIVATE smw)

# Include utils
include(${CMAKE_SOURCE_DIR}/tests/cmake/utils.cmake)

# Include SMW API tests
include(${CMAKE_SOURCE_DIR}/tests/cmake/api_tests.cmake)

# If TEE subsystem defined, include tests
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Teec AND
   DEFINED FIND_PACKAGE_MESSAGE_DETAILS_TA_dev_kit)
    set(TEE_TESTS_ENABLED ON)
    include(${CMAKE_SOURCE_DIR}/tests/cmake/tee_tests.cmake)
endif()

# If HSM subsystem defined, include tests
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Seco AND
   DEFINED FIND_PACKAGE_MESSAGE_DETAILS_ZLIBLight)
    set(HSM_TESTS_ENABLED ON)
    include(${CMAKE_SOURCE_DIR}/tests/cmake/hsm_tests.cmake)
endif()

# If ELE subsystem defined, include tests
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Ele)
    set(ELE_TESTS_ENABLED ON)
    include(${CMAKE_SOURCE_DIR}/tests/cmake/ele_tests.cmake)
endif()

# If HSM subsystem and TEE subsystem defined, include tests
if(TEE_TESTS_ENABLED AND HSM_TESTS_ENABLED)
    set(HSMTEE_TESTS ON)
    include(${CMAKE_SOURCE_DIR}/tests/cmake/hsmtee_tests.cmake)
endif()

if(TEE_TESTS_ENABLED)
    add_subdirectory(tee)
endif()

if(ELE_TESTS_ENABLED OR ENABLE_PSA_DEFAULT_ALT)
    if(NOT DEFINED PSA_ARCH_TESTS_SRC_PATH)
        message(WARNING
                "-DPSA_ARCH_TESTS_SRC_PATH="
                "<PSA Architecture Tests source path> missing\n"
                "PSA Tests are not built")
    else()
        # Include SMW PSA tests
        include(${CMAKE_SOURCE_DIR}/tests/cmake/psa_tests.cmake)

        add_subdirectory(psa)
    endif()
endif()

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake
        DESTINATION ${SMW_CTEST_TEST_FILE_DIR}
        EXCLUDE_FROM_ALL
        COMPONENT ${PROJECT_NAME})

install(FILES ${TEST_SCRIPTS_BIN}/run_simple_test.sh
        DESTINATION ${SMW_TESTS_TARGET_SCRIPTS_DIR}
        PERMISSIONS WORLD_EXECUTE OWNER_READ
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL)

install(TARGETS ${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL OPTIONAL)

add_custom_target(install_${PROJECT_NAME}
        COMMAND "${CMAKE_COMMAND}" -DCOMPONENT=${PROJECT_NAME}
                -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_install.cmake"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        VERBATIM)

if(TARGET install_tests)
    add_dependencies(install_tests install_${PROJECT_NAME})
endif()

if(TARGET build_tests)
    add_dependencies(build_tests ${PROJECT_NAME})
endif()
