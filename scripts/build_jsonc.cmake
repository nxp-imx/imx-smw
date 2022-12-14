if(NOT DEFINED CMAKE_FIND_LIBRARY_PREFIXES)
   set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
endif()

if(NOT DEFINED CMAKE_FIND_LIBRARY_SUFFIXES)
   set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
endif()

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

if(NOT DEFINED JSONC_ROOT)
    message(FATAL_ERROR "-DJSONC_ROOT=<json-c export path> missing")
endif()

if(NOT IS_ABSOLUTE ${JSONC_ROOT})
    set(JSONC_ROOT "${CMAKE_SOURCE_DIR}/${JSONC_ROOT}")
endif()

include(${CMAKE_TOOLCHAIN_FILE})

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
find_package(Jsonc)

if(JSONC_FOUND)
    message(STATUS "JSON C library already installed")
    return()
endif()

if(NOT DEFINED JSONC_SRC_PATH)
    message(FATAL_ERROR "-DJSONC_SRC_PATH=<json c source path> missing")
endif()
if(NOT IS_ABSOLUTE ${JSONC_SRC_PATH})
    set(JSONC_SRC_PATH "${CMAKE_SOURCE_DIR}/${JSONC_SRC_PATH}")
endif()

if(NOT JSONC_VERSION)
    set(JSONC_VERSION "0.15" CACHE STRING "Default JSON-C Version")
    set(JSONC_HASH "SHA256=b8d80a1ddb718b3ba7492916237bbf86609e9709fb007e7f7d4322f02341a4c6")
endif()

set(JSONC_SRC "${JSONC_SRC_PATH}/json-c-${JSONC_VERSION}")

if(NOT EXISTS ${JSONC_SRC})
    set(JSONC_URL https://s3.amazonaws.com/json-c_releases/releases)
    set(JSONC_ARCHIVE "json-c-${JSONC_VERSION}.tar.gz")

    find_file(JSONC_ARCHIVE_PATH ${JSONC_ARCHIVE} ${JSONC_SRC_PATH})
    if (NOT ${JSONC_ARCHIVE_PATH})
        message(STATUS "Downloading json-c library sources from " ${JSONC_URL})
        file(DOWNLOAD
            "${JSONC_URL}/${JSONC_ARCHIVE}"
            "${JSONC_SRC_PATH}/${JSONC_ARCHIVE}"
            EXPECTED_HASH ${JSONC_HASH}
            STATUS DL_STATUS)
    endif()

    message(STATUS "Extracting ${JSONC_ARCHIVE}")
    execute_process(COMMAND ${CMAKE_COMMAND} -E tar xvzf ${JSONC_ARCHIVE}
                    WORKING_DIRECTORY ${JSONC_SRC_PATH}
                    RESULT_VARIABLE RES)

    if(NOT ${RES} EQUAL 0)
        message(FATAL_ERROR "Cannot extract json-c: ${RES}")
    endif()
endif()

set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

set(JSONC_BUILD_DIR ${JSONC_ROOT}/jsonc-build)
execute_process(COMMAND mkdir -p ${JSONC_BUILD_DIR}
                RESULT_VARIABLE RES)

if(NOT ${RES} EQUAL 0)
    message(FATAL_ERROR "Cannot create ${JSONC_BUILD_DIR}: ${RES}")
endif()

message(STATUS "Executing ${JSONC_CMAKE}")
execute_process(COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=release ${JSONC_SRC}
                WORKING_DIRECTORY ${JSONC_BUILD_DIR}
                RESULT_VARIABLE RES)

if(NOT ${RES} EQUAL 0)
    message(FATAL_ERROR "Executing ${JSONC_CMAKE} failed: ${RES}")
endif()

message(STATUS "Building json-c library")
execute_process(COMMAND make
                WORKING_DIRECTORY ${JSONC_BUILD_DIR}
                RESULT_VARIABLE RES)

if(NOT ${RES} EQUAL 0)
    message(FATAL_ERROR "Cannot build json-c library: ${RES}")
endif()

execute_process(COMMAND mkdir -p usr/lib
                WORKING_DIRECTORY ${JSONC_ROOT}
                RESULT_VARIABLE RES)

if(NOT ${RES} EQUAL 0)
    message(FATAL_ERROR "Cannot create ${JSONC_ROOT}/lib: ${RES}")
endif()

execute_process(COMMAND mkdir -p usr/include
                WORKING_DIRECTORY ${JSONC_ROOT}
                RESULT_VARIABLE RES)

if(NOT ${RES} EQUAL 0)
    message(FATAL_ERROR "Cannot create ${JSONC_ROOT}/include: ${RES}")
endif()

file(GLOB jsonc_include ${JSONC_SRC}/*.h ${JSONC_BUILD_DIR}/*.h)
foreach(file IN LISTS jsonc_include)
    execute_process(COMMAND cp ${file} ${JSONC_ROOT}/usr/include
                    RESULT_VARIABLE RES)
    if(NOT ${RES} EQUAL 0)
        message(FATAL_ERROR "Can't copy ${file} in ${JSONC_ROOT}/usr/include: ${RES}")
    endif()
endforeach()

message(STATUS "JSON C include files are located in ${JSONC_ROOT}/usr/include")

file(GLOB jsonc_library ${JSONC_BUILD_DIR}/libjson-c*)
foreach(file IN LISTS jsonc_library)
    execute_process(COMMAND cp -P ${file} ${JSONC_ROOT}/usr/lib
                    RESULT_VARIABLE RES)
    if(NOT ${RES} EQUAL 0)
        message(FATAL_ERROR "Can't copy ${file} in ${JSONC_ROOT}/usr/lib: ${RES}")
    endif()
endforeach()

message(STATUS "JSON C library files are located in ${JSONC_ROOT}/usr/lib")
