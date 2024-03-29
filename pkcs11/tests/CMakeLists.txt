project(testsmw_pkcs11 VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wall -Wextra -Werror)
endif()

add_executable(${PROJECT_NAME} EXCLUDE_FROM_ALL "")

file(GLOB pkcs11_test *.c)
target_sources(${PROJECT_NAME} PRIVATE  ${pkcs11_test})

target_include_directories(${PROJECT_NAME} PRIVATE
                           include
                           ${CMAKE_SOURCE_DIR}/inc)

set(LIBRARY_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})

if(NOT DEFAULT_PKCS11_LIB)
  set(DEFAULT_PKCS11_LIB ${LIBRARY_PATH}/${SMW_PKCS11_LIB})
endif()

set(PKCS11_SHARE_TARGET_DIR share/smw/pkcs11)
set(PKCS11_TESTS_TARGET_DATA_DIR ${PKCS11_SHARE_TARGET_DIR}/tests)
set(PKCS11_TARGET_CONFIG_DIR ${PKCS11_SHARE_TARGET_DIR}/config)
set(PKCS11_TARGET_SCRIPTS_DIR ${PKCS11_SHARE_TARGET_DIR}/scripts)

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
    ${CMAKE_DL_LIBS}
    rt
    ${CMAKE_THREAD_LIBS_INIT})

if(NOT NO_SMW_CONFIG AND NOT DEFINED SMW_CONFIG_FILE)
  set(SMW_CONFIG_FILE "${CMAKE_INSTALL_PREFIX}/${PKCS11_TARGET_CONFIG_DIR}/default_config.txt")
  message(STATUS "SMW Config will be loaded from ${SMW_CONFIG_FILE}")
endif()

configure_file(./include/config.h.in ./include/config.h)

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

install(DIRECTORY config
        DESTINATION ${PKCS11_SHARE_TARGET_DIR}
        COMPONENT ${PROJECT_NAME}
        EXCLUDE_FROM_ALL)

install(DIRECTORY scripts
        DESTINATION ${PKCS11_SHARE_TARGET_DIR}
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE WORLD_EXECUTE
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
             COMMAND ${CMAKE_INSTALL_PREFIX}/${PKCS11_TARGET_SCRIPTS_DIR}/run_test.sh
                "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/${PROJECT_NAME} -t ${name}")
    set_tests_properties(pkcs11_${name} PROPERTIES LABELS "pkcs11;${name}")
endmacro()

pkcs11_test(get_functions)
pkcs11_test(get_info_ifs)
pkcs11_test(get_ifs)
pkcs11_test(initialize)
pkcs11_test(slot_token)
pkcs11_test(session)
pkcs11_test(object_key_ec)
pkcs11_test(object_key_cipher)
pkcs11_test(object_key_rsa)
pkcs11_test(find)
pkcs11_test(parallel)
pkcs11_test(callback)
pkcs11_test(digest)
pkcs11_test(sign_verify)
pkcs11_test(random)
pkcs11_test(encrypt_decrypt)
pkcs11_test(encrypt_decrypt_multipart)

# If TEE subsystem defined, include tests
if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Teec AND
   DEFINED FIND_PACKAGE_MESSAGE_DETAILS_TA_dev_kit)
    add_subdirectory(tee)
endif()
