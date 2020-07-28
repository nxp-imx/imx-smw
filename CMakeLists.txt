cmake_minimum_required(VERSION 3.5)

project(SecurityMiddlewareLibrary VERSION 0.1 LANGUAGES C)

include(CMakeDependentOption)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(SMW_IMPORTS_PATH "${CMAKE_SOURCE_DIR}/imports")

if(VERBOSE)
    if(NOT VERBOSE MATCHES "^[0-9]$")
        message(FATAL_ERROR "VERBOSE must be an integer")
    endif()
    if(NOT VERBOSE EQUAL 0)
        add_definitions(-DENABLE_TRACE)
    endif()
    if(${VERBOSE} GREATER 4)
        set(VERBOSE 4)
    endif()
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(${VERBOSE} GREATER 2)
            set(VERBOSE 2)
        endif()
    endif()
    add_definitions(-DTRACE_LEVEL=${VERBOSE})
    message(STATUS TRACE_LEVEL: ${VERBOSE})
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DENABLE_DEBUG)
endif()

option(ENABLE_HSM "Enable HSM subsystem" ON)
option(ENABLE_TEE "Enable TEE subsystem" ON)
option(BUILD_TEST "Build smw test suite" OFF)

option(ENABLE_KEYMGR_MODULE "Link the Key manager" ON)
cmake_dependent_option(ENABLE_HASH "Enable Hash" ON "ENABLE_KEYMGR_MODULE" OFF)
cmake_dependent_option(ENABLE_SIGN_VERIFY "Enable Sign and Verify" ON "ENABLE_KEYMGR_MODULE" OFF)

set(BUILD_SHARED_LIBS ON)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wall -Werror)
endif()
set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(OS linux)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/public ${CMAKE_SOURCE_DIR}/inc)

add_subdirectory(osal)
add_subdirectory(core)

#
# Include PKCS#11 project
#
add_subdirectory(pkcs11)

add_library(smw ${OBJ_LIST} ${INCLUDE_DIR})
set_target_properties(smw PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)
target_include_directories(smw PRIVATE ${INCLUDE_DIR} PUBLIC ${CMAKE_SOURCE_DIR}/public)
target_include_directories(smw INTERFACE "$<INSTALL_INTERFACE:include>")

FIND_PACKAGE(Threads REQUIRED)

target_link_libraries(smw PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${EXT_LIBS})

install(TARGETS smw DESTINATION lib)
install(FILES public/smw_status.h DESTINATION include/smw)
install(FILES osal/${OS}/config/default_config.txt DESTINATION share/smw)

if(BUILD_TEST)
    enable_testing()
    add_subdirectory(test)
endif()
