#[=======================================================================[.rst:
FindEla
-----------------

Finds the EdgeLock Enclave ELA libraries.

This module requires ELE to be found first, as ELA is an extension
of the ELE subsystem and uses the same installation path.

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``Ela_FOUND``
  True if the system has the ELA libraries.
``ELA_INCLUDE_DIRS``
  Include directories needed to use ELA libraries.
``ELA_LIBRARIES``
  Libraries fullname needed to link to ELA libraries.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``ELA_INCLUDE_DIR``
  the directory containing ``prime.h``.
``ELA_LIBRARY``
  the path to the ELA library.
``ELA_LIB_NAMES``
  name of the ELA library without path.

#]=======================================================================]

# ELA requires ELE to be enabled
if(NOT DEFINED ELE_ROOT)
    if(${CMAKE_FIND_PACKAGE_NAME}_FIND_REQUIRED)
        message(FATAL_ERROR "ELE_ROOT not defined. ELA requires ELE subsystem to be enabled.")
    else()
        message(STATUS "ELE_ROOT not defined. ELA requires ELE subsystem.")
        return()
    endif()
endif()

# ELA uses the same root path as ELE
if(NOT IS_ABSOLUTE ${ELE_ROOT})
    set(ELE_ROOT "${CMAKE_SOURCE_DIR}/${ELE_ROOT}")
endif()

# Find ELA library (libprime.so)
find_library(ELA_LIBRARY prime
          PATHS ${ELE_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR}
          CMAKE_FIND_ROOT_PATH_BOTH)

# Find ELA header (prime.h)
find_path(ELA_INCLUDE_DIR prime.h
          PATHS ${ELE_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR} usr/${CMAKE_INSTALL_INCLUDEDIR}/prime
                        ${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR}/prime
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(${CMAKE_FIND_PACKAGE_NAME}
    REQUIRED_VARS ELA_LIBRARY
    REASON_FAILURE_MESSAGE "ELA library (libprime.so) not found in ${ELE_ROOT}. Ensure ELA is installed in the ELE installation directory.")

get_property(MAKE_ROLE GLOBAL PROPERTY CMAKE_ROLE)

if(${CMAKE_FIND_PACKAGE_NAME}_FOUND AND NOT MAKE_ROLE STREQUAL "SCRIPT")
    get_filename_component(ELA_TOP_INCLUDE_DIR ${ELA_INCLUDE_DIR} DIRECTORY)
    set(ELA_INCLUDE_DIRS "${ELA_INCLUDE_DIR};${ELA_TOP_INCLUDE_DIR}")
    set(ELA_LIBRARIES ${ELA_LIBRARY})
    get_filename_component(ELA_LIB_NAMES ${ELA_LIBRARY} NAME)

    # Avoid redefining the target
    if(NOT TARGET Ela::Ela)
        # Define the imported target
        add_library(Ela::Ela SHARED IMPORTED GLOBAL)

        set_target_properties(Ela::Ela PROPERTIES
            IMPORTED_LOCATION "${ELA_LIBRARIES}")
    endif()

endif()

mark_as_advanced(ELA_INCLUDE_DIR ELA_TOP_INCLUDE_DIR ELA_LIBRARY ELA_LIB_NAMES)
