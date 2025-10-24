project(testsmw_pkcs11 VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wall -Wextra -Werror)
endif()

add_executable(${PROJECT_NAME} EXCLUDE_FROM_ALL "")

file(GLOB pkcs11_test *.c)
target_sources(${PROJECT_NAME} PRIVATE  ${pkcs11_test})

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    ${CMAKE_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/public)

set(LIBRARY_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})

if(NOT DEFAULT_PKCS11_LIB)
  set(DEFAULT_PKCS11_LIB ${LIBRARY_PATH}/${SMW_PKCS11_LIB})
endif()

set(PKCS11_SHARE_TARGET_DIR share/smw/pkcs11)
set(PKCS11_TESTS_TARGET_DATA_DIR ${PKCS11_SHARE_TARGET_DIR}/tests)
set(PKCS11_TARGET_SCRIPTS_DIR ${PKCS11_TESTS_TARGET_DATA_DIR}/scripts)
set(PKCS11_TARGET_SCRIPTS_DIR_FULL_PATH ${CMAKE_INSTALL_PREFIX}/${PKCS11_TARGET_SCRIPTS_DIR})
set(PKCS11_TEST_SCRIPTS_SRC ${CMAKE_CURRENT_SOURCE_DIR}/scripts)
set(PKCS11_TEST_SCRIPTS_BIN ${CMAKE_CURRENT_BINARY_DIR}/scripts)

message(STATUS "Default PKCS11 Library: ${DEFAULT_PKCS11_LIB}")

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_SOURCE_DIR}/pkcs11/import)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/pkcs11/src/include
    ${CMAKE_BINARY_DIR}/pkcs11/src/include)

find_package(Threads REQUIRED)

target_link_libraries(${PROJECT_NAME} PRIVATE
    smw
    ${CMAKE_DL_LIBS}
    rt
    m
    ${CMAKE_THREAD_LIBS_INIT})

target_link_libraries(${PROJECT_NAME} PRIVATE ${EXT_LIBS})

# If TEE subsystem defined, include tests
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Teec AND
   DEFINED FIND_PACKAGE_MESSAGE_DETAILS_TA_dev_kit)
    set(TEE_TESTS_ENABLED ON)
endif()

# If SECO subsystem defined, include tests
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Seco)
    set(SECO_TESTS_ENABLED ON)
endif()

# If ELE subsystem defined, include tests
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Ele)
    set(ELE_TESTS_ENABLED ON)
endif()

configure_file(./include/config.h.in ./include/config.h)
configure_file(${PKCS11_TEST_SCRIPTS_SRC}/setup_test.sh.in
               ${PKCS11_TEST_SCRIPTS_BIN}/setup_test.sh @ONLY)
configure_file(${PKCS11_TEST_SCRIPTS_SRC}/cleanup_test.sh.in
               ${PKCS11_TEST_SCRIPTS_BIN}/cleanup_test.sh @ONLY)

#
# Installation procedure done as separated make target
#
install(TARGETS ${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL OPTIONAL)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake
        DESTINATION ${PKCS11_TESTS_TARGET_DATA_DIR}
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL)

install(FILES ${PKCS11_TEST_SCRIPTS_BIN}/setup_test.sh
        DESTINATION ${PKCS11_TARGET_SCRIPTS_DIR}
        PERMISSIONS WORLD_READ WORLD_EXECUTE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL)

install(FILES ${PKCS11_TEST_SCRIPTS_BIN}/cleanup_test.sh
        DESTINATION ${PKCS11_TARGET_SCRIPTS_DIR}
        PERMISSIONS WORLD_READ WORLD_EXECUTE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL)

install(FILES scripts/test_lib.sh
        DESTINATION ${PKCS11_TARGET_SCRIPTS_DIR}
        PERMISSIONS WORLD_READ WORLD_EXECUTE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL)

install(FILES scripts/run_test.sh
        DESTINATION ${PKCS11_TARGET_SCRIPTS_DIR}
        PERMISSIONS WORLD_READ WORLD_EXECUTE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL)

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

enable_testing()

#
# Add ctest definition
#
macro(pkcs11_test name)
    add_test(NAME pkcs11_${name}
             COMMAND ${PKCS11_TARGET_SCRIPTS_DIR_FULL_PATH}/run_test.sh
               "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/${PROJECT_NAME} -t ${name}")
    set_tests_properties(pkcs11_${name} PROPERTIES LABELS "pkcs11;${name}")
    set_tests_properties(pkcs11_${name} PROPERTIES SKIP_RETURN_CODE 1)
    set_tests_properties(pkcs11_${name} PROPERTIES FIXTURES_REQUIRED PKCS11_Test_Fixture)
endmacro()

add_test(NAME SetupTest COMMAND "${PKCS11_TARGET_SCRIPTS_DIR_FULL_PATH}/setup_test.sh")
set_tests_properties(SetupTest PROPERTIES FIXTURES_SETUP PKCS11_Test_Fixture)

pkcs11_test(get_functions)
pkcs11_test(get_info_ifs)
pkcs11_test(get_ifs)
pkcs11_test(initialize)
pkcs11_test(slot_token)
pkcs11_test(session)
pkcs11_test(object_key_ec)
pkcs11_test(object_key_edwards)
pkcs11_test(object_key_cipher)
pkcs11_test(object_key_rsa)
pkcs11_test(find)
pkcs11_test(find_ext)
pkcs11_test(parallel)
pkcs11_test(callback)
pkcs11_test(digest)
pkcs11_test(digest_multipart)
pkcs11_test(sign_verify)
pkcs11_test(sign_verify_message)
pkcs11_test(sign_verify_multipart)
pkcs11_test(sign_verify_multipart_message)
pkcs11_test(random)
pkcs11_test(encrypt_decrypt)
pkcs11_test(encrypt_decrypt_aead)
pkcs11_test(encrypt_decrypt_message)
pkcs11_test(encrypt_decrypt_multipart)
pkcs11_test(encrypt_decrypt_multipart_message)
pkcs11_test(asymmetric_encryption)
pkcs11_test(data_storage)
pkcs11_test(objects)
pkcs11_test(derive_key)
pkcs11_test(operation_state)
pkcs11_test(object_profile)
pkcs11_test(object_cert)
pkcs11_test(performance)
pkcs11_test(derive_key_tls1_3)
pkcs11_test(derive_key_tls1_2)

add_test(NAME CleanupTest COMMAND "${PKCS11_TARGET_SCRIPTS_DIR_FULL_PATH}/cleanup_test.sh")
set_tests_properties(CleanupTest PROPERTIES FIXTURES_CLEANUP PKCS11_Test_Fixture)
