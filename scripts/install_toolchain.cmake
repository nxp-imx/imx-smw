#
# Install toochain
#
include(FindWget)

if(NOT ${WGET_FOUND})
	message(FATAL_ERROR "Can not install toolchain")
endif()

if(NOT ${TOOLCHAIN_ARCHIVE_DIR})
	message(FATAL_ERROR "Bad toolchain name and version")
endif()

set(TOOLCHAIN_ARCHIVE "${TOOLCHAIN_AR_DIR}.tar.xz")
set(TOOLCHAIN_PATH ${CMAKE_SOURCE_DIR}/toolchains)

find_file(UPLOADED_FILE ${TOOLCHAIN_ARCHIVE} ${TOOLCHAIN_PATH})
if(NOT UPLOADED_FILE)
	message("wget ${TOOLCHAIN_WGET}${TOOLCHAIN_ARCHIVE}")
	file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/toolchains")

	execute_process(
		COMMAND ${WGET_EXECUTABLE} ${TOOLCHAIN_WGET}${TOOLCHAIN_ARCHIVE}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/toolchains
		RESULT_VARIABLE wget_res
	)

	if(NOT ${wget_res} EQUAL 0)
		message(FATAL_ERROR "Can not upload toolchain")
	endif()
endif()

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/toolchains/${TOOLCHAIN_AR_DIR})
	message("extracting ${TOOLCHAIN_ARCHIVE} ...")
	execute_process(
		COMMAND ${CMAKE_COMMAND} -E tar xf ${TOOLCHAIN_ARCHIVE}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/toolchains
		RESULT_VARIABLE tar_res
	)

	if(NOT ${tar_res} EQUAL 0)
		message(FATAL_ERROR "Can not extract toolchain :${tar_res}")
	endif()
endif()

set(TOOLCHAIN_PATH ${TOOLCHAIN_PATH}/${TOOLCHAIN_AR_DIR}/bin)
