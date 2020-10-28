#[=======================================================================[.rst:
FindJSONC
-------

Finds the JSON-C library.

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``JSONC_FOUND``
  True if the system has the JSON-C library.
``JSONC_INCLUDE_DIR``
  Include directory needed to use JSONC library.
``JSONC_LIBRARY``
  Library needed.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``JSONC_INCLUDE_DIR``
  Include directory needed to use JSONC library..
``JSONC_LIBRARY``
  The path to the JSONC library.

#]=======================================================================]
if(NOT DEFINED JSONC_ROOT)
    message("JSONC_ROOT not defined")
endif()

if(DEFINED JSONC_ROOT AND NOT IS_ABSOLUTE ${JSONC_ROOT})
    set(JSONC_ROOT "${CMAKE_SOURCE_DIR}/${JSONC_ROOT}")
endif()

find_library(JSONC_LIBRARY json-c
             PATHS ${JSONC_ROOT}/lib
             PATH_SUFFIXES usr/lib lib
             CMAKE_FIND_ROOT_PATH_BOTH)
find_path(JSONC_INCLUDE_DIR NAMES json.h json_config.h
          PATHS ${JSONC_ROOT}/include ${JSONC_ROOT}/include/json-c
          PATH_SUFFIXES usr/include include
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(JSONC REQUIRED_VARS JSONC_LIBRARY
                                                      JSONC_INCLUDE_DIR)
mark_as_advanced(JSONC_LIBRARY JSONC_INCLUDE_DIR)
