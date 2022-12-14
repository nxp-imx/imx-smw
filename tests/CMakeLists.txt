cmake_minimum_required(VERSION 3.5)

project(smwtest VERSION 2.2 LANGUAGES C)

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

set(TEST_CMD ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_SCRIPTS_DIR}/run_simple_test.sh)
set(TEST_KEYMGR_SUSPEND_RESUME_CMD
    ${CMAKE_INSTALL_PREFIX}/${SMW_TESTS_TARGET_SCRIPTS_DIR}/run_keymgr_suspend_resume.sh)

configure_file(${TEST_SRC_INC}/paths.h.in ${TEST_BIN_INC}/paths.h)
configure_file(${TEST_SCRIPTS_SRC}/run_simple_test.sh.in
               ${TEST_SCRIPTS_BIN}/run_simple_test.sh @ONLY)
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
               engine/run_app.c
               engine/run_thread.c
               engine/sign_verify.c
               engine/test_engine.c
               engine/util.c
               engine/util_app.c
               engine/util_list.c
               engine/util_key.c
               engine/util_sign.c
               engine/util_tlv.c
               engine/util_context.c
               engine/util_cipher.c
               engine/util_thread.c
               engine/util_file.c
               engine/util_mutex.c
               engine/util_sem.c
               engine/util_log.c
               engine/util_cond.c
               engine/util_ipc.c
               engine/operation_context.c
               ${CMAKE_CURRENT_BINARY_DIR}/engine/util_status.c
               $<$<CONFIG:Debug>:engine/util_debug.c>)

target_include_directories(${PROJECT_NAME} PRIVATE
                           ${TEST_SRC_INC}
                           ${TEST_BIN_INC}
                           ${JSONC_INCLUDE_DIR}
                           ${CMAKE_SOURCE_DIR}/inc)

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
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Ele AND
   DEFINED FIND_PACKAGE_MESSAGE_DETAILS_ZLIBLight)
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
              ${TEST_SCRIPTS_BIN}/run_keymgr_suspend_resume.sh
              ${TEST_SCRIPTS_SRC}/${SUSPEND_RESUME_SCRIPT_NAME}
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
