#
# Check Secure Enclave libraries present or build them to install it in the
# SECO_ROOT
#
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
include(${CMAKE_TOOLCHAIN_FILE})

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
find_package(Seco)

if(SECO_FOUND)
    message(STATUS "SECO libraries already installed")
    return()
endif()

if(NOT SECO_FOUND)
    #
    # Check if the Secure Enclave sources are present to build
    #
    if(NOT DEFINED SECO_SRC_PATH)
        message(FATAL_ERROR "-DSECO_SRC_PATH=<secure enclave source path> missing")
    endif()

    if(NOT IS_ABSOLUTE ${SECO_SRC_PATH})
        set(SECO_SRC_PATH"${CMAKE_SOURCE_DIR}/${SECO_SRC_PATH}")
    endif()

    find_file(SECO_MAKEFILE Makefile ${SECO_SRC_PATH})

    if(SECO_MAKEFILE)
        set(ENV{CC} ${CMAKE_C_COMPILER})
        set(ENV{AR} ${CMAKE_AR})

        message(STATUS "Building EdgeLock Enclave libs")
        set(SECO_MAKE_ARGS clean libs install PLAT=seco COMPATIBLE_MACHINE=mx8dxl-nxp-bsp DESTDIR=${SECO_ROOT})
        execute_process(COMMAND make ${SECO_MAKE_ARGS}
            WORKING_DIRECTORY ${SECO_SRC_PATH}
            RESULT_VARIABLE res)

        if(NOT ${res} EQUAL 0)
            message(FATAL_ERROR "\nFailed to build EdgeLock Enclave libs "
                "from ${SECO_SRC_PATH}\n")
        endif()
    else()
        message(FATAL_ERROR "\nEdgeLock Enclave libs can't be built, "
            "Makefile not found in ${SECO_SRC_PATH}.\n")
    endif()
endif()
