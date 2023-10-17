#
# Check OPTEE TA Development kit present or build optee to install it in the
# TA_DEV_KIT_ROOT
#
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
   message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

include(${CMAKE_TOOLCHAIN_FILE})

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
find_package(TA_dev_kit)

if(TA_DEV_KIT_FOUND)
    message(STATUS "OPTEE TA Development kit already installed")
    return()
endif()

#
# Prepare build environment
#
execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpmachine OUTPUT_VARIABLE arch)
if(${arch} MATCHES "^aarch64")
    set(TA_EXPORT export-ta_arm64)
elseif(${arch} MATCHES "^arm")
    set(TA_EXPORT export-ta_arm32)
else()
    message(FATAL_ERROR "Machine architecture ${arch} not supported")
endif()

if(NOT DEFINED PLATFORM)
    message(FATAL_ERROR "OPTEE OS build platform not defined")
endif()
message(STATUS "Platform used to build OPTEE OS is ${PLATFORM}")

if(NOT DEFINED BUILD_DIR)
    set(BUILD_DIR ${CMAKE_BINARY_DIR}/ext_build)
elseif(NOT IS_ABSOLUTE ${BUILD_DIR})
    set(BUILD_DIR ${CMAKE_BINARY_DIR}/${BUILD_DIR})
endif()

#
# Check if the OPTEE sources is present to build
#
if(NOT DEFINED TA_DEV_KIT_ROOT AND NOT DEFINED OPTEE_OS_SRC_PATH)
    if(NOT DEFINED TA_DEV_KIT_ROOT)
        message(STATUS "-DTA_DEV_KIT_ROOT=<OPTEE TA export path> missing")
    endif()
    if(NOT DEFINED OPTEE_OS_SRC_PATH)
        message(STATUS "-DOPTEE_OS_SRC_PATH=<OPTEE OS source path> missing")
    endif()
    return()
endif()

if(NOT IS_ABSOLUTE ${TA_DEV_KIT_ROOT})
    set(TA_DEV_KIT_ROOT "${CMAKE_SOURCE_DIR}/${TA_DEV_KIT_ROOT}")
endif()

if(NOT IS_ABSOLUTE ${OPTEE_OS_SRC_PATH})
    set(OPTEE_OS_SRC_PATH "${CMAKE_SOURCE_DIR}/${OPTEE_OS_SRC_PATH}")
endif()

# Get number of cores to optimise build process
execute_process(COMMAND nproc OUTPUT_VARIABLE NB_CORES)
string(STRIP ${NB_CORES} NB_CORES)

set(CMD_OPTEE_OS_BUILD "make")
list(APPEND CMD_OPTEE_OS_BUILD "-j${NB_CORES}")
list(APPEND CMD_OPTEE_OS_BUILD "CFG_TEE_CORE_LOG_LEVEL=1")
list(APPEND CMD_OPTEE_OS_BUILB "CFG_TEE_TA_LOG_LEVEL=0")
list(APPEND CMD_OPTEE_OS_BUILD "CFG_WERROR=y")
list(APPEND CMD_OPTEE_OS_BUILD "PLATFORM=${PLATFORM}")
list(APPEND CMD_OPTEE_OS_BUILD "O=${BUILD_DIR}/build.${PLATFORM}")

if(${arch} MATCHES "^aarch64")
    list(APPEND CMD_OPTEE_OS_BUILD "CROSS_COMPILE64=${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}")
    list(APPEND CMD_OPTEE_OS_BUILD "all")
else()
    list(APPEND CMD_OPTEE_OS_BUILD "CROSS_COMPILE=${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}")
    list(APPEND CMD_OPTEE_OS_BUILD "all")
    list(APPEND CMD_OPTEE_OS_BUILD "uTee")
endif()

message(STATUS "Building OPTEE OS - ${PLATFORM}")

execute_process(COMMAND ${CMD_OPTEE_OS_BUILD}
                WORKING_DIRECTORY ${OPTEE_OS_SRC_PATH}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "\n${res}\nFailed to build OPTEE OS from "
                        "${OPTEE_OS_SRC_PATH}\n")
endif()

get_filename_component(COPY_DIR ${TA_DEV_KIT_ROOT} DIRECTORY)
file(COPY ${BUILD_DIR}/build.${PLATFORM}/${TA_EXPORT}
     DESTINATION ${COPY_DIR})
