set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:tee> PARENT_SCOPE)

macro(find_teec_lib export_dir found)
    find_library(TEEC_LIB_FILE ${TEEC_LIB_NAME} ${export_dir}/usr/lib
                 CMAKE_FIND_ROOT_PATH_BOTH)
    find_path(TEEC_INCLUDE_PATH tee_client_api.h ${export_dir}/usr/include
              CMAKE_FIND_ROOT_PATH_BOTH)

    if(TEEC_LIB_FILE AND TEEC_INCLUDE_PATH)
        set(${found} True)
    else()
        set(${found} False)
    endif()
endmacro()

macro(find_optee_os_export_files export_dir found)
    find_path(OPTEE_INCLUDE_FILES tee_internal_api.h ${export_dir}/include
              CMAKE_FIND_ROOT_PATH_BOTH)
    find_path(OPTEE_MK_FILES ta_dev_kit.mk ${export_dir}/mk
              CMAKE_FIND_ROOT_PATH_BOTH)

    if(OPTEE_INCLUDE_FILES AND OPTEE_MK_FILES)
        set(${found} True)
    else()
        set(${found} False)
    endif()
endmacro()

macro(check_optee_arch)
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpmachine
                    OUTPUT_VARIABLE toolchain_arch)

    if(${toolchain_arch} MATCHES "^aarch64")
        set(toolchain_arch 64)
    elseif(${toolchain_arch} MATCHES "^arm")
        set(toolchain_arch 32)
    endif()

    if(${OPTEE_OS_TA_EXPORT_DIR} MATCHES "arm64$")
        set(optee_arch 64)
    elseif(${OPTEE_OS_TA_EXPORT_DIR} MATCHES "arm32$")
        set(optee_arch 32)
    endif()


    if(NOT ${toolchain_arch} EQUAL ${optee_arch})
        message(FATAL_ERROR "\nToolchain architecture is ${toolchain_arch}bits "
                            "but optee os is ${optee_arch}bits\n")
    endif()
endmacro()

string(REGEX REPLACE "-gcc$" "-" CROSS_COMPILE  ${CMAKE_C_COMPILER})
set(TEEC_LIB_NAME "teec")
set(TA_BINARY 11b5c4aa-6d20-11ea-bc55-0242ac130003)
set(TA_FILE ${TA_BINARY}.ta)
set(OPTEE_DEFAULT_PLATFORM mx8qmmek)
set(TA_EXPORT_32 export-ta_arm32)
set(TA_EXPORT_64 export-ta_arm64)

#
# As by default TEE subsystem is ON, if OPTEE_CLIENT_EXPORT_DIR is not defined
# it's set to the path to imx-optee-client source files that should be located
# at the same level as smw source files.
# If defined, make path absolute if it's not the case
#
if(NOT DEFINED OPTEE_CLIENT_EXPORT_DIR)
    set(OPTEE_CLIENT_EXPORT_DIR ${CMAKE_SOURCE_DIR}/../imx-optee-client)
elseif(NOT IS_ABSOLUTE ${OPTEE_CLIENT_EXPORT_DIR})
    set(OPTEE_CLIENT_EXPORT_DIR
        "${CMAKE_SOURCE_DIR}/${OPTEE_CLIENT_EXPORT_DIR}")
endif()

#
# As by default TEE subsystem is ON, if OPTEE_OS_TA_EXPORT_DIR is not defined
# it's set to the path to imx-optee-os source files that should be located
# at the same level as smw source files.
# If defined, make path absolute if it's not the case
#
if(NOT DEFINED OPTEE_OS_TA_EXPORT_DIR)
    set(OPTEE_OS_TA_EXPORT_DIR ${CMAKE_SOURCE_DIR}/../imx-optee-os)
elseif(NOT IS_ABSOLUTE ${OPTEE_OS_TA_EXPORT_DIR})
    set(OPTEE_OS_TA_EXPORT_DIR "${CMAKE_SOURCE_DIR}/${OPTEE_OS_TA_EXPORT_DIR}")
endif()

#
# Look for optee client library and export files
#
find_teec_lib(${OPTEE_CLIENT_EXPORT_DIR} TEEC_LIB_FOUND)

#
# If library and export files not found build imx optee client
#
if(NOT TEEC_LIB_FOUND)
    find_file(TEEC_MAKEFILE Makefile ${OPTEE_CLIENT_EXPORT_DIR})

    if(TEEC_MAKEFILE)
        set(ENV{CC} ${CMAKE_C_COMPILER})
        set(ENV{AR} ${CMAKE_AR})
        set(OUTPUT_DIR ${CMAKE_BINARY_DIR}/optee-client)

        get_filename_component(TEEC_SOURCES ${TEEC_MAKEFILE} DIRECTORY)

        message(STATUS "Building OPTEE Client")
        execute_process(COMMAND make O=${OUTPUT_DIR}
                        WORKING_DIRECTORY ${TEEC_SOURCES}
                        RESULT_VARIABLE TEEC_BUILD_RES)

        if(NOT ${TEEC_BUILD_RES} EQUAL 0)
            message(FATAL_ERROR "\nFailed to build OPTEE Client from "
                                "${OPTEE_CLIENT_EXPORT_DIR}\n")
        endif()

        set(OPTEE_CLIENT_EXPORT_DIR ${OUTPUT_DIR}/export)
        message(STATUS "OPTEE Client export directory:"
                       " ${OPTEE_CLIENT_EXPORT_DIR}")

        find_teec_lib(${OPTEE_CLIENT_EXPORT_DIR} TEEC_LIB_FOUND)
        if(NOT TEEC_LIB_FOUND)
            message(FATAL_ERROR "\nOPTEE Client export directory not valid\n")
        endif()
    else()
        message(FATAL_ERROR "\nOPTEE Client can't be build, Makefile"
                            " not found in ${OPTEE_CLIENT_EXPORT_DIR}\n")
    endif()
endif()

#
# Look for OPTEE OS export files
#
find_optee_os_export_files(${OPTEE_OS_TA_EXPORT_DIR} TA_EXPORT_FOUND)

#
# If export files not found build imx optee os
#
if(NOT TA_EXPORT_FOUND)
    find_file(NXP_BUILD_SCRIPT nxp_build.sh ${OPTEE_OS_TA_EXPORT_DIR}/scripts)

    if(NXP_BUILD_SCRIPT)
        set(ENV{CROSS_COMPILE64} ${CROSS_COMPILE})
        set(ENV{O} ${CMAKE_BINARY_DIR})

        if(NOT DEFINED PLATFORM)
            set(PLATFORM ${OPTEE_DEFAULT_PLATFORM})
        endif()
        message(STATUS "Platform used to build OPTEE OS is ${PLATFORM}")

        # Get number of cores to optimise build process
        execute_process(COMMAND nproc OUTPUT_VARIABLE NB_CORES)
        set(ENV{NB_CORES} ${NB_CORES})

        message(STATUS "Building OPTEE OS")
        execute_process(COMMAND scripts/nxp_build.sh ${PLATFORM}
                        OUTPUT_QUIET
                        WORKING_DIRECTORY ${OPTEE_OS_TA_EXPORT_DIR}
                        RESULT_VARIABLE build_optee_os)

        if(NOT ${build_optee_os} EQUAL 0)
            message(FATAL_ERROR "\nFailed to build OPTEE OS from "
                                "${OPTEE_OS_TA_EXPORT_DIR}\n")
        endif()

        set(OPTEE_BUILD_DIR ${CMAKE_BINARY_DIR}/build.${PLATFORM})
        set(OPTEE_OS_TA_EXPORT_DIR ${OPTEE_BUILD_DIR}/${TA_EXPORT_32})

        find_optee_os_export_files(${OPTEE_OS_TA_EXPORT_DIR} FOUND)
        if(NOT FOUND)
            set(OPTEE_OS_TA_EXPORT_DIR ${OPTEE_BUILD_DIR}/${TA_EXPORT_64})
            find_optee_os_export_files(${OPTEE_OS_TA_EXPORT_DIR} FOUND)
            if (NOT FOUND)
                message(FATAL_ERROR "\nCan't find OPTEE OS export directory"
                                    " in ${OPTEE_BUILD_DIR}\n")
            endif()
        endif()

        message(STATUS "OPTEE OS export directory: ${OPTEE_OS_TA_EXPORT_DIR}")
    else()
        message(FATAL_ERROR "\nOPTEE OS can't be build, "
                            "build script not found\n")
    endif()
endif()

#
# Check if toolchain architecture is same as OPTEE OS export
#
check_optee_arch()

set(OPTEE_CLIENT_INCLUDE_DIR ${TEEC_INCLUDE_PATH})
set(TEE_COMMON_INCLUDE ./common)
set(INCLUDE_DIR ${INCLUDE_DIR} ${TEE_COMMON_INCLUDE}
                ${OPTEE_CLIENT_INCLUDE_DIR})

add_library(tee OBJECT "")
set_target_properties(tee PROPERTIES C_VISIBILITY_PRESET hidden)
target_sources(tee PRIVATE
               tee.c
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c>)
target_include_directories(tee PRIVATE ${INCLUDE_DIR})

set(EXT_LIBS ${EXT_LIBS}
    $<$<BOOL:${TEEC_LIB_FILE}>:${TEEC_LIB_FILE}>
    PARENT_SCOPE)

# Invoke TA Makefile
set(TA_MAKEFILE_PATH ${CMAKE_SOURCE_DIR}/core/subsystems/tee/ta)

set(TA_BUILD_DIR ${CMAKE_BINARY_DIR}/ta)

execute_process(COMMAND make -C ${TA_MAKEFILE_PATH}
                BINARY=${TA_BINARY}
                TA_EXPORT_DIR=${OPTEE_OS_TA_EXPORT_DIR}
                TA_CROSS_COMPILE=${CROSS_COMPILE}
                TA_LOG_LEVEL=${VERBOSE}
		O=${TA_BUILD_DIR}
                RESULT_VARIABLE TA_MAKE_RES)

if(NOT ${TA_MAKE_RES} EQUAL 0)
     message(FATAL_ERROR "\nFailed to build SMW Trusted Application\n")
endif()

install(FILES ${TA_BUILD_DIR}/${TA_FILE} DESTINATION ${DESTDIR}/lib/optee_armtz)
