#
# Install zlib
#

if(NOT SMW_IMPORTS_PATH)
    message(FATAL_ERROR "Imports path not defined")
endif()

set(ZLIB_NAME "zlib")
set(ZLIB_VERSION "1.2.11" CACHE STRING "Default zlib Version")
set(ZLIB_HASH "SHA256=4ff941449631ace0d4d203e3483be9dbc9da454084111f97ea0a2114e19bf066")
set(ZLIB_SERVER "http://www.zlib.net")
set(ZLIB_AR_DIR "${ZLIB_NAME}-${ZLIB_VERSION}")
set(ZLIB_ARCHIVE "${ZLIB_AR_DIR}.tar.xz")
set(ZLIB_URL ${ZLIB_SERVER})
set(ZLIB_PREFIX "${SMW_IMPORTS_PATH}")

macro(find_zlib export_dir found)
    find_path(ZLIB_LIB_PATH libz.so PATHS ${export_dir}/lib NO_CMAKE_SYSTEM_PATH)
    find_path(ZLIB_INCLUDE_PATH zlib.h PATHS ${export_dir}/include NO_CMAKE_SYSTEM_PATH)

    if(ZLIB_LIB_PATH AND ZLIB_INCLUDE_PATH)
        set(${found} True)
    else()
        set(${found} False)
    endif()
endmacro()

find_zlib(${ZLIB_PREFIX} ZLIB_FOUND)

if(ZLIB_FOUND)
    message(STATUS "zlib already installed")
    return()
endif()

if(NOT EXISTS ${SMW_IMPORTS_PATH}/${ZLIB_AR_DIR})
    find_file(ZLIB_ARCHIVE_PATH ${ZLIB_ARCHIVE} ${SMW_IMPORTS_PATH})
    if(NOT ZLIB_ARCHIVE_PATH)
        message(STATUS "Downloading ${ZLIB_ARCHIVE} from ${ZLIB_URL}")
        file(DOWNLOAD
             "${ZLIB_URL}/${ZLIB_ARCHIVE}"
             "${SMW_IMPORTS_PATH}/${ZLIB_ARCHIVE}"
             EXPECTED_HASH ${ZLIB_HASH}
        )
    endif()

    message(STATUS "Extracting ${ZLIB_ARCHIVE}")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xf ${ZLIB_ARCHIVE}
        WORKING_DIRECTORY ${SMW_IMPORTS_PATH}
        RESULT_VARIABLE res
    )

    if(NOT ${res} EQUAL 0)
        message(FATAL_ERROR "Cannot extract zlib :${res}")
    endif()
endif()

set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

message(STATUS "Configuring ${ZLIB_AR_DIR}")
set(ZLIB_CONFIGURE "./configure")
set(ZLIB_CONFIGURE_ARGS "--prefix=${ZLIB_PREFIX}" "--enable-shared")
message(STATUS "Executing ${ZLIB_CONFIGURE} ${ZLIB_CONFIGURE_ARGS}")
execute_process(
    COMMAND ${ZLIB_CONFIGURE} ${ZLIB_CONFIGURE_ARGS}
    WORKING_DIRECTORY ${SMW_IMPORTS_PATH}/${ZLIB_AR_DIR}
    RESULT_VARIABLE res
)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot configure zlib :${res}")
endif()

message(STATUS "Installing ${ZLIB_AR_DIR}")
set(ZLIB_MAKE make)
set(ZLIB_MAKE_ARGS clean all install)
execute_process(
    COMMAND ${ZLIB_MAKE} ${ZLIB_MAKE_ARGS}
    WORKING_DIRECTORY ${SMW_IMPORTS_PATH}/${ZLIB_AR_DIR}
    RESULT_VARIABLE res
)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot install zlib :${res}")
endif()

find_zlib(${ZLIB_PREFIX} ZLIB_FOUND)

if(NOT ZLIB_FOUND)
    message(FATAL_ERROR "Failed to install zlib")
endif()
