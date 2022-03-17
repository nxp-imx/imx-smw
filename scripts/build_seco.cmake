#
# Check seco libraries present or build them to install it in the
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
find_package(ZLIBLight)

if(SECO_FOUND AND ZLIB_FOUND)
    message(STATUS "Seco libraries already installed")
    return()
endif()

if(NOT ZLIB_FOUND)
    include(${CMAKE_SOURCE_DIR}/scripts/build_zlib.cmake)
    find_package(ZLIBLight REQUIRED)
endif()

if(NOT SECO_FOUND)
    #
    # Check if the Seco sources are present to build
    #
    if(NOT DEFINED SECO_SRC_PATH)
        message(FATAL_ERROR "-DSECO_SRC_PATH=<seco source path> missing")
    endif()

    if(NOT IS_ABSOLUTE ${SECO_SRC_PATH})
        set(SECO_SRC_PATH"${CMAKE_SOURCE_DIR}/${SECO_SRC_PATH}")
    endif()

    find_file(SECO_MAKEFILE Makefile ${SECO_SRC_PATH})
    if(SECO_MAKEFILE)
        set(ENV{CC} ${CMAKE_C_COMPILER})
        set(ENV{AR} ${CMAKE_AR})
        set(ENV{CPATH} $ENV{CPATH}:${ZLIB_INCLUDE_DIR})

        set(HSM_LIB_FILE hsm_lib.a)
        set(NVM_LIB_FILE seco_nvm_manager.a)

        message(STATUS "Building seco libs")
        set(SECO_MAKE_ARGS clean ${HSM_LIB_FILE} ${NVM_LIB_FILE})
        execute_process(COMMAND make ${SECO_MAKE_ARGS}
                        WORKING_DIRECTORY ${SECO_SRC_PATH}
                        RESULT_VARIABLE res)

        if(NOT ${res} EQUAL 0)
            message(FATAL_ERROR "\nFailed to build seco libs "
                                "from ${SECO_SRC_PATH}\n")
        endif()

        file(GLOB SECO_EXPORTED_LIBS LIST_DIRECTORIES False
             "${SECO_SRC_PATH}/*.a")

        file(COPY ${SECO_EXPORTED_LIBS} DESTINATION ${SECO_ROOT}/usr/lib)
        file(COPY "${SECO_SRC_PATH}/include" DESTINATION ${SECO_ROOT}/usr)
    else()
         message(FATAL_ERROR "\nSeco libs can't be built, Makefile not found"
                             "in ${SECO_SRC_PATH}.\n")
    endif()
endif()
