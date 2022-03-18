#
# Install toochain
#
if(NOT TOOLCHAIN_AR_DIR)
    message(FATAL_ERROR "Bad toolchain name and version")
endif()

set(TOOLCHAIN_ARCHIVE "${TOOLCHAIN_AR_DIR}.tar.xz")
if (NOT TOOLCHAIN_PATH)
    set(TOOLCHAIN_PATH ${CMAKE_SOURCE_DIR}/toolchains)
endif()

if(NOT EXISTS ${TOOLCHAIN_PATH}/${TOOLCHAIN_AR_DIR})
    find_file(UPLOADED_FILE ${TOOLCHAIN_ARCHIVE} ${TOOLCHAIN_PATH})
    if(NOT UPLOADED_FILE)
        message(STATUS "Downloading ${TOOLCHAIN_ARCHIVE} from ${TOOLCHAIN_URL}")
        file(DOWNLOAD
             "${TOOLCHAIN_URL}/${TOOLCHAIN_ARCHIVE}"
             "${TOOLCHAIN_PATH}/${TOOLCHAIN_ARCHIVE}"
             EXPECTED_HASH ${TOOLCHAIN_HASH}
             INACTIVITY_TIMEOUT 10
             SHOW_PROGRESS
        )
    endif()

    message(STATUS "Extracting ${TOOLCHAIN_ARCHIVE}")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xf ${TOOLCHAIN_ARCHIVE}
        WORKING_DIRECTORY ${TOOLCHAIN_PATH}
        RESULT_VARIABLE res
    )

    if(NOT ${res} EQUAL 0)
        message(FATAL_ERROR "Cannot extract toolchain :${res}")
    endif()
else()
    message(STATUS "Toolchain already installed")
endif()
