#[=======================================================================[.rst:
FindSeco
-------

Finds the Seco NVM and Seco library.

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``SECO_FOUND``
  True if the system has the EdgeLock Enclave (SECO) libraries.
``SECO_INCLUDE_DIRS``
  Include directories needed to use EdgeLock Enclave (SECO) libraries.
``SECO_LIBRARIES``
  Libraries fullname needed to link to EdgeLock Enclave (SECO) libraries.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``SECO_INCLUDE_DIR``
  the directory containing ``hsm_api.h``.
``SECO_LIBRARY``
  the path to the EdgeLock Enclave (SECO) library.

#]=======================================================================]
if(NOT DEFINED SECO_ROOT)
    message("SECO_ROOT not defined")
endif()

if(DEFINED SECO_ROOT AND NOT IS_ABSOLUTE ${SECO_ROOT})
    set(SECO_ROOT "${CMAKE_SOURCE_DIR}/${SECO_ROOT}")
endif()

find_library(SECO_LIBRARY _hsm
          PATHS ${SECO_ROOT} ${SECO_ROOT}/usr
          PATH_SUFFIXES ${CMAKE_INSTALL_LIBDIR}
          CMAKE_FIND_ROOT_PATH_BOTH)
find_path(SECO_INCLUDE_DIR hsm_api.h
          PATHS ${SECO_ROOT} ${SECO_ROOT}/usr
          PATH_SUFFIXES ${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR}/hsm
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  SECO_LIBRARY SECO_INCLUDE_DIR)

if(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
    get_filename_component(SECO_TOP_INCLUDE_DIR ${SECO_INCLUDE_DIR} DIRECTORY)
    set(SECO_LIBRARIES ${SECO_LIBRARY})
    set(SECO_INCLUDE_DIRS "${SECO_INCLUDE_DIR};${SECO_TOP_INCLUDE_DIR}")
endif()

mark_as_advanced(SECO_LIBRARY SECO_INCLUDE_DIR SECO_TOP_INCLUDE_DIR)
