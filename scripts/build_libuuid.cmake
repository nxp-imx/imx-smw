#
# Check libuuid is present or build it to install it in the LIBUUID_EXPORT
#
if(NOT DEFINED CMAKE_FIND_LIBRARY_PREFIXES)
   set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
endif()

if(NOT DEFINED CMAKE_FIND_LIBRARY_SUFFIXES)
   set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
endif()

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
   message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

if(NOT DEFINED LIBUUID_CONFIG_ROOT)
    message(FATAL_ERROR "-DLIBUUID_CONFIG_ROOT=<libuuid export path> missing")
endif()

if(NOT IS_ABSOLUTE ${LIBUUID_CONFIG_ROOT})
    set(LIBUUID_CONFIG_ROOT "${CMAKE_SOURCE_DIR}/${LIBUUID_CONFIG_ROOT}")
endif()

include(${CMAKE_TOOLCHAIN_FILE})

set(LIBUUID_NAME "util-linux")
set(LIBUUID_VERSION "2.38" CACHE STRING "Default libuuid Version")
set(LIBUUID_HASH "SHA256=c31d4e54f30b56b0f7ec8b342658c07de81378f2c067941c2b886da356f8ad42")
set(LIBUUID_URL "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.38/")
set(LIBUUID_AR_DIR "${LIBUUID_NAME}-${LIBUUID_VERSION}")
set(LIBUUID_ARCHIVE "${LIBUUID_AR_DIR}.tar.gz")

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
find_package(LibUUID)

if(LIBUUID_FOUND)
    message(STATUS "libuuid already installed")
    return()
endif()

if(NOT DEFINED LIBUUID_SRC_PATH)
    message(FATAL_ERROR "-DLIBUUID_SRC_PATH=<source path> missing")
endif()
if(NOT IS_ABSOLUTE ${LIBUUID_SRC_PATH})
    set(LIBUUID_SRC_PATH"${CMAKE_SOURCE_DIR}/${LIBUUID_SRC_PATH}")
endif()

set(LIBUUID_SRC "${LIBUUID_SRC_PATH}/${LIBUUID_AR_DIR}")

if(NOT EXISTS ${LIBUUID_SRC})
    find_file(LIBUUID_ARCHIVE_PATH ${LIBUUID_ARCHIVE} ${LIBUUID_SRC_PATH})
    if(NOT LIBUUID_ARCHIVE_PATH)
        message(STATUS "Downloading ${LIBUUID_ARCHIVE} from ${LIBUUID_URL}")
        file(DOWNLOAD
             "${LIBUUID_URL}/${LIBUUID_ARCHIVE}"
             "${LIBUUID_SRC_PATH}/${LIBUUID_ARCHIVE}"
             EXPECTED_HASH ${LIBUUID_HASH})
    endif()

    message(STATUS "Extracting ${LIBUUID_ARCHIVE}")
    execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf ${LIBUUID_ARCHIVE}
                    WORKING_DIRECTORY ${LIBUUID_SRC_PATH}
                    RESULT_VARIABLE res)

    if(NOT ${res} EQUAL 0)
        message(FATAL_ERROR "Cannot extract UUID library archive :${res}")
    endif()
endif()

#
# Build library
#
set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

message(STATUS "Configuring ${LIBUUID_AR_DIR}")
set(LIBUUID_CONFIGURE "./configure")
set(LIBUUID_CONFIGURE_ARGS "--prefix=${LIBUUID_CONFIG_ROOT}" "--enable-shared" "--with-sysroot=${LIBUUID_CONFIG_ROOT}" "--disable-all-programs" "--enable-libuuid" "--target=${TOOLCHAIN_NAME}" "--host=${TOOLCHAIN_NAME}")
message(STATUS "Executing ${LIBUUID_CONFIGURE} ${LIBUUID_CONFIGURE_ARGS}")
execute_process(COMMAND ${LIBUUID_CONFIGURE} ${LIBUUID_CONFIGURE_ARGS}
                WORKING_DIRECTORY ${LIBUUID_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot configure libuuid ${res}")
endif()

message(STATUS "Building ${LIBUUID_AR_DIR}")
set(LIBUUID_MAKE_ARGS clean all install)
execute_process(COMMAND make ${LIBUUID_MAKE_ARGS}
                WORKING_DIRECTORY ${LIBUUID_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot build libuuid ${res}")
endif()
