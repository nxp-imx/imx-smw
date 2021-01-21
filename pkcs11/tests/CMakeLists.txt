project(testsmw_pkcs11 VERSION 1.0 LANGUAGES C)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wall -Wextra -Werror)
endif()

add_executable(${PROJECT_NAME} "")

file(GLOB pkcs11_test *.c)
target_sources(${PROJECT_NAME} PRIVATE  ${pkcs11_test})

target_include_directories(${PROJECT_NAME} PRIVATE include)

set(LIBRARY_PATH ${CMAKE_INSTALL_PREFIX}/lib)

if(NOT DEFAULT_PKCS11_LIB)
  set(DEFAULT_PKCS11_LIB ${LIBRARY_PATH}/${SMW_PKCS11_LIB})
endif()

set(PKCS11_SHARE_TARGET_DIR share/smw/pkcs11)
set(PKCS11_TESTS_TARGET_DATA_DIR ${PKCS11_SHARE_TARGET_DIR}/tests)
set(PKCS11_TARGET_CONFIG_DIR ${PKCS11_SHARE_TARGET_DIR}/config)

message(STATUS "Default PKCS11 Library: ${DEFAULT_PKCS11_LIB}")

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_SOURCE_DIR}/pkcs11/import
    ${CMAKE_SOURCE_DIR}/pkcs11/src/include)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
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

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake
        DESTINATION ${PKCS11_TESTS_TARGET_DATA_DIR})
install(DIRECTORY config DESTINATION ${PKCS11_SHARE_TARGET_DIR})

macro(pkcs11_test name)
    add_test(NAME pkcs11_${name}
             COMMAND ${CMAKE_INSTALL_PREFIX}/bin/${PROJECT_NAME} -t ${name})
    set_tests_properties(pkcs11_${name} PROPERTIES LABELS "pkcs11;${name}")
endmacro()

pkcs11_test(get_functions)
pkcs11_test(get_info_ifs)
pkcs11_test(get_ifs)
pkcs11_test(initialize)
pkcs11_test(slot_token)
pkcs11_test(session)
pkcs11_test(object)
pkcs11_test(find)
pkcs11_test(parallel)
pkcs11_test(callback)
