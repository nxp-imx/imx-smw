#
# Check OPTEE Clientlibrary present or build it to install it in the
# TEEC_EXPORT
#
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
   message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

include(${CMAKE_TOOLCHAIN_FILE})

set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)

if(NOT DEFINED LIBUUID_CONFIG_ROOT)
    get_filename_component(LIBUUID_CONFIG_PATH ${TOOLCHAIN_BIN_PATH} DIRECTORY)
else()
    set(LIBUUID_CONFIG_PATH ${LIBUUID_CONFIG_ROOT})
endif()

find_package(Teec)

if(TEEC_FOUND)
    message(STATUS "OPTEE Client and TA Development kit already installed")
    return()
endif()

if(NOT DEFINED BUILD_DIR)
    set(BUILD_DIR ${CMAKE_BINARY_DIR}/ext_build)
elseif(NOT IS_ABSOLUTE ${BUILD_DIR})
    set(BUILD_DIR ${CMAKE_BINARY_DIR}/${BUILD_DIR})
endif()

#
# Check if the OPTEE Client sources is present to build
#
if(NOT DEFINED TEEC_ROOT OR NOT DEFINED TEEC_SRC_PATH)
    if(NOT DEFINED TEEC_ROOT)
        message(STATUS "-DTEEC_ROOT=<OPTEE Client export path> missing")
    endif()
    if(NOT DEFINED TEEC_SRC_PATH)
        message(STATUS "-DTEEC_SRC_PATH=<OPTEE Client source path> missing")
    endif()
    return()
endif()

find_file(LIBUUID_CONFIG NAMES uuid.pc PATHS ${LIBUUID_CONFIG_PATH}
          PATH_SUFFIXES lib/pkgconfig pkgconfig)

if(LIBUUID_CONFIG)
    get_filename_component(LIBUUID_CONFIG_DIR ${LIBUUID_CONFIG} DIRECTORY)
else()
    if(NOT DEFINED LIBUUID_CONFIG_ROOT)
        message(WARNING "-DLIBUUID_CONFIG_ROOT=<OPTEE Client library uuid"
                         " configuration path> missing")
    else()
        message(WARNING "Configuration of libuuid (uuid.pc) not found in"
                        " ${LIBUUID_CONFIG_ROOT}")
    endif()
endif()

find_file(PKG_CONFIG_BIN NAMES pkg-config PATHS ${PKG_CONFIG_ROOT})

if(PKG_CONFIG_BIN)
    if(NOT DEFINED PKG_CONFIG_ROOT)
        message(WARNING "-DPKG_CONFIG_ROOT=<pkg-config path> missing")
    else()
        message(WARNING "Tool pkg-config not found in ${PKG_CONFIG_ROOT}")
    endif()
endif()


if(NOT IS_ABSOLUTE ${TEEC_ROOT})
    set(TEEC_ROOT "${CMAKE_SOURCE_DIR}/${TEEC_ROOT}")
endif()

if(NOT IS_ABSOLUTE ${TEEC_SRC_PATH})
    set(TEEC_SRC_PATH "${CMAKE_SOURCE_DIR}/${TEEC_SRC_PATH}")
endif()

find_file(TEEC_MAKEFILE Makefile ${TEEC_SRC_PATH})

if(TEEC_MAKEFILE)
    set(ENV{CC} ${CMAKE_C_COMPILER})
    set(ENV{AR} ${CMAKE_AR})
    set(ENV{PKG_CONFIG_PATH} "${LIBUUID_CONFIG_DIR}")
    set(ENV{PKG_CONFIG} "${PKG_CONFIG_BIN}")

    set(OUTPUT_DIR ${BUILD_DIR}/optee-client)

    message(STATUS "Building OPTEE Client")
    execute_process(COMMAND make O=${OUTPUT_DIR}
                    WORKING_DIRECTORY ${TEEC_SRC_PATH}
                    RESULT_VARIABLE res)

    if(NOT ${res} EQUAL 0)
        message(FATAL_ERROR "\nFailed to build OPTEE Client from "
                            "${TEEC_SRC_PATH}\n")
    endif()

    file(COPY ${OUTPUT_DIR}/export/usr DESTINATION ${TEEC_ROOT})
else()
    message(FATAL_ERROR "\nOPTEE Client can't be build, Makefile"
                        " not found in ${TEEC_SRC_PATH}\n")
endif()
