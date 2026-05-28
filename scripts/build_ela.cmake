#
# Check ELA library is present or build it to install it in the ELE_ROOT
#
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
include(${CMAKE_TOOLCHAIN_FILE})

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)

# ELA requires ELE to be configured
if(NOT DEFINED ELE_ROOT)
    message(FATAL_ERROR "-DELE_ROOT=<ELE export path> missing. ELA requires ELE subsystem.")
endif()

if(NOT IS_ABSOLUTE ${ELE_ROOT})
    set(ELE_ROOT "${CMAKE_SOURCE_DIR}/${ELE_ROOT}")
endif()

# Check if ELA is already installed
find_package(Ela QUIET)

if(Ela_FOUND)
    message(STATUS "ELA library already installed")
    message(STATUS "  Library: ${ELA_LIBRARY}")
    message(STATUS "  Headers: ${ELA_INCLUDE_DIR}")
    return()
endif()

message(STATUS "ELA library not found in ${ELE_ROOT}")

#
# Check if the ELE sources are present to build ELA library.
# ELA is part of the ELE source tree
#
if(NOT DEFINED ELE_SRC_PATH)
    message(FATAL_ERROR "-DELE_SRC_PATH=<ELE source path> missing. ELA is built from ELE sources.")
endif()

if(NOT IS_ABSOLUTE ${ELE_SRC_PATH})
    set(ELE_SRC_PATH "${CMAKE_SOURCE_DIR}/${ELE_SRC_PATH}")
endif()

# Check if Makefile exists in ELE source path
find_file(ELE_MAKEFILE Makefile ${ELE_SRC_PATH})

if(NOT ELE_MAKEFILE)
    message(FATAL_ERROR "\nELA library can't be built, "
                        "Makefile not found in ${ELE_SRC_PATH}.\n")
endif()

# Set up build environment
set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

message(STATUS "Building ELA library from ${ELE_SRC_PATH}")
message(STATUS "Installing to ${ELE_ROOT}")

set(ELA_MAKE_ARGS clean libs install PLAT=prime DESTDIR=${ELE_ROOT})

message(STATUS "Executing: make ${ELA_MAKE_ARGS}")
execute_process(COMMAND make ${ELA_MAKE_ARGS}
    WORKING_DIRECTORY ${ELE_SRC_PATH}
    RESULT_VARIABLE res
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "\nFailed to build ELA library from ${ELE_SRC_PATH}\n"
                        "Error code: ${res}\n"
                        "Output: ${output}\n"
                        "Error: ${error}\n")
endif()

message(STATUS "ELA library built successfully")