#
# Check SQLite3 is present or build it to install it in the SQLite3_ROOT
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

if(NOT DEFINED SQLite3_ROOT)
    message(FATAL_ERROR "-DSQLite3_ROOT=<SQLite3 export path> missing")
endif()

if(NOT IS_ABSOLUTE ${SQLite3_ROOT})
    set(SQLite3_ROOT "${CMAKE_SOURCE_DIR}/${SQLite3_ROOT}")
endif()

include(${CMAKE_TOOLCHAIN_FILE})

set(SQLite3_NAME "sqlite-autoconf")
set(SQLite3_VERSION "3450100" CACHE STRING "Default SQLite3 Version")
set(SQLite3_HASH "SHA256=cd9c27841b7a5932c9897651e20b86c701dd740556989b01ca596fcfa3d49a0a")
set(SQLite3_URL "https://www.sqlite.org/2024/")
set(SQLite3_AR_DIR "${SQLite3_NAME}-${SQLite3_VERSION}")
set(SQLite3_ARCHIVE "${SQLite3_AR_DIR}.tar.gz")

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
cmake_policy(SET CMP0074 NEW)
find_package(SQLite3)

if(SQLite3_FOUND)
    message(STATUS "SQLite3 already installed")
    return()
endif()

if(NOT DEFINED SQLite3_SRC_PATH)
    message(FATAL_ERROR "-DSQLite3_SRC_PATH=<source path> missing")
endif()
if(NOT IS_ABSOLUTE ${SQLite3_SRC_PATH})
    set(SQLite3_SRC_PATH"${CMAKE_SOURCE_DIR}/${SQLite3_SRC_PATH}")
endif()

set(SQLite3_SRC "${SQLite3_SRC_PATH}/${SQLite3_AR_DIR}")

if(NOT EXISTS ${SQLite3_SRC})
    find_file(SQLite3_ARCHIVE_PATH ${SQLite3_ARCHIVE} ${SQLite3_SRC_PATH})
    if(NOT SQLite3_ARCHIVE_PATH)
        message(STATUS "Downloading ${SQLite3_ARCHIVE} from ${SQLite3_URL}")
        file(DOWNLOAD
             "${SQLite3_URL}/${SQLite3_ARCHIVE}"
             "${SQLite3_SRC_PATH}/${SQLite3_ARCHIVE}"
             EXPECTED_HASH ${SQLite3_HASH})
    endif()

    message(STATUS "Extracting ${SQLite3_ARCHIVE}")
    execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf ${SQLite3_ARCHIVE}
                    WORKING_DIRECTORY ${SQLite3_SRC_PATH}
                    RESULT_VARIABLE res)

    if(NOT ${res} EQUAL 0)
        message(FATAL_ERROR "Cannot extract SQLite library archive :${res}")
    endif()
endif()

#
# Build library
#
set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

message(STATUS "Configuring ${SQLite3_AR_DIR}")
set(SQLite3_CONFIGURE "./configure")
set(SQLite3_CONFIGURE_ARGS "--prefix=${SQLite3_ROOT}" "--enable-threadsafe"
	"--disable-static-shell" "--with-sysroot=${SQLite3_ROOT}"
	"--target=${TOOLCHAIN_NAME}" "--host=${TOOLCHAIN_NAME}")
message(STATUS "Executing ${SQLite3_CONFIGURE} ${SQLite3_CONFIGURE_ARGS}")
execute_process(COMMAND ${SQLite3_CONFIGURE} ${SQLite3_CONFIGURE_ARGS}
                WORKING_DIRECTORY ${SQLite3_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot configure SQLite3 ${res}")
endif()

message(STATUS "Building ${SQLite3_AR_DIR}")
set(SQLite3_MAKE_ARGS clean all install)
execute_process(COMMAND make ${SQLite3_MAKE_ARGS} CFLAGS="-DUSE_PREAD -DSQLITE_ENABLE_COLUMN_METADATA"
                WORKING_DIRECTORY ${SQLite3_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot build SQLite3 ${res}")
endif()
