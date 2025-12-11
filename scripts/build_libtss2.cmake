#
# Check libtss2 is present or build it to install it in the TSS2_ROOT
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

if(NOT DEFINED TSS2_ROOT)
    message(FATAL_ERROR "-DTSS2_ROOT=<TSS2 export path> missing")
endif()

if(NOT IS_ABSOLUTE ${TSS2_ROOT})
    set(TSS2_ROOT "${CMAKE_SOURCE_DIR}/${TSS2_ROOT}")
endif()

include(${CMAKE_TOOLCHAIN_FILE})

set(TSS2_NAME "tpm2-tss")
set(TSS2_VERSION "4.1.3" CACHE STRING "Default TSS2 Version")
set(TSS2_HASH "SHA256=37f1580200ab78305d1fc872d89241aaee0c93cbe85bc559bf332737a60d3be8")
set(TSS2_URL "https://github.com/tpm2-software/tpm2-tss/releases/download/${TSS2_VERSION}")
set(TSS2_AR_DIR "${TSS2_NAME}-${TSS2_VERSION}")
set(TSS2_ARCHIVE "${TSS2_AR_DIR}.tar.gz")

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
cmake_policy(SET CMP0074 NEW)

if(TSS2_FOUND)
    message(STATUS "TSS2 already installed")
    return()
endif()

if(NOT DEFINED TSS2_SRC_PATH)
    message(FATAL_ERROR "-DTSS2_SRC_PATH=<source path> missing")
endif()
if(NOT IS_ABSOLUTE ${TSS2_SRC_PATH})
    set(TSS2_SRC_PATH"${CMAKE_SOURCE_DIR}/${TSS2_SRC_PATH}")
endif()

set(TSS2_SRC "${TSS2_SRC_PATH}/${TSS2_AR_DIR}")

if(NOT EXISTS ${TSS2_SRC})
    find_file(TSS2_ARCHIVE_PATH ${TSS2_ARCHIVE} ${TSS2_SRC_PATH})
    if(NOT TSS2_ARCHIVE_PATH)
        message(STATUS "Downloading ${TSS2_ARCHIVE} from ${TSS2_URL}")
        file(DOWNLOAD
             "${TSS2_URL}/${TSS2_ARCHIVE}"
             "${TSS2_SRC_PATH}/${TSS2_ARCHIVE}"
             EXPECTED_HASH ${TSS2_HASH})
    endif()

    message(STATUS "Extracting ${TSS2_ARCHIVE}")
    execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf ${TSS2_ARCHIVE}
                    WORKING_DIRECTORY ${TSS2_SRC_PATH}
                    RESULT_VARIABLE res)

    if(NOT ${res} EQUAL 0)
        message(FATAL_ERROR "Cannot extract TSS2 library archive :${res}")
    endif()
endif()

#
# Build library
#
set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

message(STATUS "Configuring ${TSS2_AR_DIR}")
set(TSS2_CONFIGURE "./configure")
set(TSS2_CONFIGURE_ARGS
    "--prefix=${TSS2_ROOT}"
    "--disable-esys"
    "--disable-fapi"
    "--disable-policy"
    "--disable-tcti-cmd"
    "--disable-tcti-device"
    "--disable-tcti-libtpms"
    "--disable-tcti-mssim"
    "--disable-tcti-pcap"
    "--disable-tcti-spi-helper"
    "--disable-tcti-spi-ltt2go"
    "--disable-tcti-spidev"
    "--disable-tcti-spi-ftdi"
    "--disable-tcti-i2c-helper"
    "--disable-tcti-i2c-ftdi"
    "--disable-tcti-smtpm"
    "--disable-doxygen-doc"
    "--enable-nodl"
	"--target=${TOOLCHAIN_NAME}"
    "--host=${TOOLCHAIN_NAME}"
    )
message(STATUS "Executing ${TSS2_CONFIGURE} ${TSS2_CONFIGURE_ARGS}")
execute_process(COMMAND ${TSS2_CONFIGURE} ${TSS2_CONFIGURE_ARGS}
                WORKING_DIRECTORY ${TSS2_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot configure TSS2 ${res}")
endif()

message(STATUS "Building ${TSS2_AR_DIR}")
set(TSS2_MAKE_ARGS clean all install)
execute_process(COMMAND make ${TSS2_MAKE_ARGS}
                WORKING_DIRECTORY ${TSS2_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot build TSS2 ${res}")
endif()
