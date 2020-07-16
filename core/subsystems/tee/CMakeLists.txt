set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:tee> PARENT_SCOPE)

macro(find_teec_lib export_dir found)
    find_file(TEEC_LIB_FILE ${TEEC_LIB_NAME} ${export_dir}/usr/lib)
    find_path(TEEC_INCLUDE_PATH tee_client_api.h ${export_dir}/usr/include)

    if(TEEC_LIB_FILE AND TEEC_INCLUDE_PATH)
        set(${found} True)
    else()
        set(${found} False)
    endif()
endmacro()

set(TEEC_LIB_NAME "libteec.a")

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
