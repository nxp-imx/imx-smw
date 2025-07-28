#[=======================================================================[.rst:
FindEle
-------

Finds the EdgeLock Enclave (ELE) libraries.

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``Ele_FOUND``
  True if the system has the EdgeLock Enclave libraries.
``ELE_INCLUDE_DIRS``
  Include directories needed to use EdgeLock Enclave libraries.
``ELE_LIBRARIES``
  Libraries fullname needed to link to EdgeLock Enclave libraries.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``ELE_INCLUDE_DIR``
  the directory containing ``hsm_api.h``.
``ELE_LIBRARIES``
  the path to the EdgeLock Enclave library.
``ELE_LIB_NAMES``
  name of the EdgeLock Enclave library without path.

#]=======================================================================]
if(NOT DEFINED ELE_ROOT)
    message("ELE_ROOT not defined")
endif()

if(DEFINED ELE_ROOT AND NOT IS_ABSOLUTE ${ELE_ROOT})
    set(ELE_ROOT "${CMAKE_SOURCE_DIR}/${ELE_ROOT}")
endif()

find_library(ELE_LIBRARY ele_hsm
          PATHS ${ELE_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR}
          CMAKE_FIND_ROOT_PATH_BOTH)

find_path(ELE_INCLUDE_DIR hsm_api.h
          PATHS ${ELE_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR} usr/${CMAKE_INSTALL_INCLUDEDIR}/hsm
                        ${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR}/hsm
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(${CMAKE_FIND_PACKAGE_NAME}
    REQUIRED_VARS ELE_LIBRARY)

if(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
  get_filename_component(ELE_TOP_INCLUDE_DIR ${ELE_INCLUDE_DIR} DIRECTORY)
  set(ELE_INCLUDE_DIRS "${ELE_INCLUDE_DIR};${ELE_TOP_INCLUDE_DIR}")
  set(ELE_LIBRARIES ${ELE_LIBRARY})
  get_filename_component(ELE_LIB_NAMES ${ELE_LIBRARY} NAME)

  # Avoid redefining the target
  if(NOT TARGET Ele::Ele)
        # Define the imported target
        add_library(Ele::Ele SHARED IMPORTED GLOBAL)

        set_target_properties(Ele::Ele PROPERTIES
            IMPORTED_LOCATION "${ELE_LIBRARIES}")
  endif()

endif()

mark_as_advanced(ELE_LIBRARY ELE_INCLUDE_DIR ELE_TOP_INCLUDE_DIR ELE_LIB_NAMES)
