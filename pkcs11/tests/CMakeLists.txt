project(testsmw_pkcs11 VERSION 1.0 LANGUAGES C)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wall -Wextra -Werror)
endif()

add_executable(${PROJECT_NAME} "")

file(GLOB pkcs11_test *.c)
target_sources(${PROJECT_NAME} PRIVATE  ${pkcs11_test})

target_include_directories(${PROJECT_NAME} PRIVATE include)

set(LIBRARY_PATH ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

if(NOT DEFAULT_PKCS11_LIB)
  set(DEFAULT_PKCS11_LIB ${LIBRARY_PATH}/libsmw_pkcs11.so)
endif()

message(STATUS "Default PKCS11 Library: ${DEFAULT_PKCS11_LIB}")

target_include_directories(${PROJECT_NAME} PUBLIC
	${CMAKE_SOURCE_DIR}/pkcs11/import
	${CMAKE_SOURCE_DIR}/pkcs11/src/include)

target_include_directories(${PROJECT_NAME} PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}/include
	${CMAKE_CURRENT_SOURCE_DIR}/include
	${CMAKE_BINARY_DIR}/pkcs11/src/include)

target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_DL_LIBS})
set(SMW_CONFIG_FILE_PATH ${CMAKE_BINARY_DIR}/bin)

configure_file(./include/config.h.in ./include/config.h)

file(COPY config DESTINATION ${SMW_CONFIG_FILE_PATH})
