#[=======================================================================[.rst:
FindTeec
-------

Finds the TEE Client library.

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``Teec_FOUND``
  True if the system has the TEE Client library.
``TEEC_INCLUDE_DIR``
  Include directory needed to use TEE Client.
``TEEC_LIBRARY``
  Library needed to link to TEE Client.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``TEEC_INCLUDE_DIR``
  The directory containing ``tee_client_api.h``.
``TEEC_LIBRARIES``
  The path to the TEE Client library.
``TEEC_LIB_NAMES``
  Name of the TEE Client library without path.

#]=======================================================================]
if(NOT DEFINED TEEC_ROOT)
    message("TECC_ROOT not defined")
endif()

if(DEFINED TEEC_ROOT AND NOT IS_ABSOLUTE ${TEEC_ROOT})
    set(TEEC_ROOT "${CMAKE_SOURCE_DIR}/${TEEC_ROOT}")
endif()

find_library(TEEC_LIBRARY teec
             PATHS ${TEEC_ROOT}
             PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR}
             CMAKE_FIND_ROOT_PATH_BOTH)
find_path(TEEC_INCLUDE_DIR tee_client_api.h
          PATHS ${TEEC_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR}
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(${CMAKE_FIND_PACKAGE_NAME}
    REQUIRED_VARS TEEC_LIBRARY)

# Create the imported target
if(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
  set(TEEC_LIBRARIES ${TEEC_LIBRARY})
  get_filename_component(TEEC_LIB_NAMES ${TEEC_LIBRARY} NAME)
  get_filename_component(TEEC_LIB_PATHS ${TEEC_LIBRARY} DIRECTORY)

  # Avoid redefining the target
  if(NOT TARGET Teec::Teec)

      # Define the imported target
      add_library(Teec::Teec SHARED IMPORTED GLOBAL)

      set_target_properties(Teec::Teec PROPERTIES
          IMPORTED_LOCATION "${TEEC_LIBRARIES}")
  endif()
endif()

mark_as_advanced(TEEC_INCLUDE_DIR TEEC_LIBRARY TEEC_LIB_NAMES)
