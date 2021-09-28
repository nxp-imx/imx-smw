cmake_minimum_required(VERSION 3.5)

project(smwtest VERSION 2.0 LANGUAGES C)

if(NOT DEFINED JSONC_ROOT)
    message(STATUS "Tests not enabled, JSONC_ROOT not defined")
    return()
endif()

find_package(Jsonc REQUIRED)

enable_testing()

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

set(SUSPEND_RESUME_SCRIPT_NAME suspend_resume.sh)

message(STATUS "Tests enabled")
message(STATUS "    JSON C Library: ${JSONC_LIBRARY}")
message(STATUS "    JSON C Include dir: ${JSONC_INCLUDE_DIR}")

configure_file(${TEST_SRC_INC}/paths.h.in ${TEST_BIN_INC}/paths.h)
configure_file(${TEST_SCRIPTS_SRC}/run_simple_test.sh.in
               ${TEST_SCRIPTS_BIN}/run_simple_test.sh)
configure_file(${TEST_SCRIPTS_SRC}/run_keymgr_suspend_resume.sh.in
               ${TEST_SCRIPTS_BIN}/run_keymgr_suspend_resume.sh
               @ONLY)

#
# Use custom command with dependency to ensure that the
# util_status.c is regrenerated each time smw_status.h change
#
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/engine/util_status.c
       COMMAND "${CMAKE_COMMAND}" -DENUM="smw_status_code"
               -DINPUT="${CMAKE_SOURCE_DIR}/public/smw_status.h"
               -DSRC="${CMAKE_CURRENT_SOURCE_DIR}/engine/util_status.c.in"
               -DDST="${CMAKE_CURRENT_BINARY_DIR}/engine/util_status.c"
               -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/enum_to_string.cmake
       DEPENDS ${CMAKE_SOURCE_DIR}/public/smw_status.h
       WORKING_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(${PROJECT_NAME}
               EXCLUDE_FROM_ALL
               engine/cipher.c
               engine/config.c
               engine/hash.c
               engine/hmac.c
               engine/info.c
               engine/keymgr.c
               engine/keymgr_derive.c
               engine/rng.c
               engine/run.c
               engine/sign_verify.c
               engine/test_engine.c
               engine/util.c
               engine/util_list.c
               engine/util_key.c
               engine/util_sign.c
               engine/util_tlv.c
               engine/util_context.c
               engine/util_cipher.c
               engine/operation_context.c
               ${CMAKE_CURRENT_BINARY_DIR}/engine/util_status.c)

target_include_directories(${PROJECT_NAME}
                           PRIVATE ${TEST_SRC_INC} ${TEST_BIN_INC}
                                   ${JSONC_INCLUDE_DIR}
                           PUBLIC ${CMAKE_SOURCE_DIR}/public
                                  ${CMAKE_SOURCE_DIR}/inc)

target_link_libraries(${PROJECT_NAME} PRIVATE ${JSONC_LIBRARY})
target_link_libraries(${PROJECT_NAME} PRIVATE smw)

set(TEST_CMD ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_SCRIPTS_DIR}/run_simple_test.sh)
set(TEST_KEYMGR_SUSPEND_RESUME_CMD
    ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_SCRIPTS_DIR}/run_keymgr_suspend_resume.sh)

# Include utils
include(${CMAKE_SOURCE_DIR}/tests/cmake/utils.cmake)

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
        DESTINATION ${SMW_CTEST_TEST_FILE_DIR}
        EXCLUDE_FROM_ALL
        COMPONENT ${PROJECT_NAME})

install(FILES ${TEST_SCRIPTS_BIN}/run_simple_test.sh
              ${TEST_SCRIPTS_BIN}/run_keymgr_suspend_resume.sh
              ${TEST_SCRIPTS_SRC}/${SUSPEND_RESUME_SCRIPT_NAME}
        DESTINATION ${SMW_TESTS_TARGET_SCRIPTS_DIR}
        PERMISSIONS WORLD_EXECUTE OWNER_READ
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL)

install(TARGETS ${PROJECT_NAME}
        DESTINATION ${SMW_TESTS_TARGET_BIN_DIR}
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
