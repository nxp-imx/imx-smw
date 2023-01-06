#
# Check Secure Enclave libraries present or build them to install it in the
# ELE_ROOT
#
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
   message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
include(${CMAKE_TOOLCHAIN_FILE})

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
find_package(Ele)
find_package(ZLIBLight)

if(ELE_FOUND)
    message(STATUS "ELE libraries already installed")
    return()
endif()

if(NOT ELE_FOUND)
    #
    # Check if the Secure Enclave sources are present to build
    #
    if(NOT DEFINED ELE_SRC_PATH)
        message(FATAL_ERROR "-DELE_SRC_PATH=<secure enclave source path> missing")
    endif()

    if(NOT IS_ABSOLUTE ${ELE_SRC_PATH})
        set(ELE_SRC_PATH"${CMAKE_SOURCE_DIR}/${ELE_SRC_PATH}")
    endif()

    find_file(ELE_MAKEFILE Makefile ${ELE_SRC_PATH})
    if(ELE_MAKEFILE)
        set(ENV{CC} ${CMAKE_C_COMPILER})
        set(ENV{AR} ${CMAKE_AR})

        message(STATUS "Building EdgeLock Enclave libs")
        set(ELE_MAKE_ARGS clean libs install PLAT=ele DESTDIR=${ELE_ROOT})
        execute_process(COMMAND make ${ELE_MAKE_ARGS}
                        WORKING_DIRECTORY ${ELE_SRC_PATH}
                        RESULT_VARIABLE res)

        if(NOT ${res} EQUAL 0)
            message(FATAL_ERROR "\nFailed to build EdgeLock Enclave libs "
                    "from ${ELE_SRC_PATH}\n")
        endif()
    else()
         message(FATAL_ERROR "\nEdgeLock Enclave libs can't be built, "
                 "Makefile not found in ${ELE_SRC_PATH}.\n")
    endif()
endif()
