cmake_minimum_required(VERSION 3.5)

project(smwtest VERSION 1.0 LANGUAGES C)

if(NOT DEFINED JSONC_ROOT)
    message(STATUS "Tests not enabled, JSONC_ROOT not defined")
    return()
endif()

find_package(JSONC REQUIRED)

set(SMW_TESTS_TARGET_BIN_DIR bin)
set(SMW_TESTS_TARGET_DATA_DIR share/smw/tests)
set(SMW_CTEST_TEST_FILE_DIR ${SMW_TESTS_TARGET_DATA_DIR})
set(DEFAULT_OUT_STATUS_DIR ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_DATA_DIR})
set(SMW_TESTS_TARGET_SCRIPTS_DIR ${SMW_TESTS_TARGET_DATA_DIR}/scripts)
set(SMW_TESTS_TARGET_DEF_DIR ${SMW_TESTS_TARGET_DATA_DIR}/test_definition)
set(SMW_TESTS_TARGET_DEF_DIR_FULL_PATH ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_DEF_DIR})
set(SMW_TESTS_TARGET_CONFIG_DIR ${SMW_TESTS_TARGET_DATA_DIR}/config)

set(TEST_DEF_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test_definition)
set(SMW_CONFIG_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/config)

set(TEST_BIN_INC ${CMAKE_CURRENT_BINARY_DIR}/engine/inc)
set(TEST_SRC_INC ${CMAKE_CURRENT_SOURCE_DIR}/engine/inc)
set(TEST_SCRIPTS_SRC ${CMAKE_CURRENT_SOURCE_DIR}/scripts)
set(TEST_SCRIPTS_BIN ${CMAKE_CURRENT_BINARY_DIR}/scripts)

message(STATUS "Tests enabled")
message(STATUS "    JSON C Library: ${JSONC_LIBRARY}")
message(STATUS "    JSON C Include dir: ${JSONC_INCLUDE_DIR}")

configure_file(${TEST_SRC_INC}/paths.h.in ${TEST_BIN_INC}/paths.h)
configure_file(${TEST_SCRIPTS_SRC}/run_simple_test.sh.in
               ${TEST_SCRIPTS_BIN}/run_simple_test.sh)

add_executable(${PROJECT_NAME}
               engine/crypto.c
               engine/keymgr.c
               engine/run.c
               engine/test_engine.c
               engine/util.c)

target_include_directories(${PROJECT_NAME}
                           PRIVATE ${TEST_SRC_INC} ${TEST_BIN_INC}
                                   ${JSONC_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME} PRIVATE ${JSONC_LIBRARY})
target_link_libraries(${PROJECT_NAME} PRIVATE smw)

set(TEST_CMD ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_SCRIPTS_DIR}/run_simple_test.sh)

# Labels
set(UNITARY_LABEL U)
set(FUNCTIONAL_LABEL F)
set(API_LABEL API)
set(TEE_LABEL TEE)
set(HSM_LABEL HSM)
set(DELETE_LABEL Delete)
set(EXPORT_LABEL Export)
set(GENERATE_LABEL Generate)
set(HASH_LABEL Hash)
set(IMPORT_LABEL Import)
set(KEYMGR_LABEL Keymgr)

install(DIRECTORY DESTINATION ${SMW_TESTS_TARGET_CONFIG_DIR})
install(DIRECTORY DESTINATION ${SMW_TESTS_TARGET_DEF_DIR})

# Include SMW API tests
include(${CMAKE_SOURCE_DIR}/tests/cmake/api_tests.cmake)

# If TEE subsystem defined, include tests
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_TEEC AND
   DEFINED FIND_PACKAGE_MESSAGE_DETAILS_TA_DEV_KIT)
    set(TEE_TESTS ON)
    include(${CMAKE_SOURCE_DIR}/tests/cmake/tee_tests.cmake)
endif()

# If HSM subsystem defined, include tests
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_SECO AND
   DEFINED FIND_PACKAGE_MESSAGE_DETAILS_ZLIB)
    set(HSM_TESTS ON)
    include(${CMAKE_SOURCE_DIR}/tests/cmake/hsm_tests.cmake)
endif()

#
# TODO: Include multi subsystem tests -> multi_tests.cmake
#       Switch values of <SUBSYSTEM>_TESTS add tests
#

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake
        DESTINATION ${SMW_CTEST_TEST_FILE_DIR})
install(FILES ${TEST_SCRIPTS_BIN}/run_simple_test.sh
        DESTINATION ${SMW_TESTS_TARGET_SCRIPTS_DIR}
        PERMISSIONS WORLD_EXECUTE OWNER_READ)
install(TARGETS ${PROJECT_NAME} DESTINATION ${SMW_TESTS_TARGET_BIN_DIR})
