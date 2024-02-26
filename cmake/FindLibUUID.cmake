#[=======================================================================[.rst:
FindLIBUUID
-------------

Find the LIBUUID includes and library.

Result Variables
^^^^^^^^^^^^^^^^
This will define the following variables:

``LIBUUID_FOUND``
True if the system has the LIBUUID library.
``LIBUUID_CONFIG_DIR``
LIBUUID pkg-config directory.

#]=======================================================================]
if(NOT DEFINED LIBUUID_CONFIG_ROOT)
    message("LIBUUID_CONFIG_ROOT not defined")
endif()

if(DEFINED LIBUUID_CONFIG_ROOT AND NOT IS_ABSOLUTE ${LIBUUID_CONFIG_ROOT})
    set(LIBUUID_CONFIG_ROOT "${CMAKE_SOURCE_DIR}/${LIBUUID_CONFIG_ROOT}")
endif()

find_path(LIBUUID_CONFIG_DIR uuid.pc
          PATHS ${LIBUUID_CONFIG_ROOT}
          PATH_SUFFIXES lib/pkgconfig pkgconfig
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  LIBUUID_CONFIG_DIR)
mark_as_advanced(LIBUUID_CONFIG_DIR LIBUUID_FOUND)
