#[=======================================================================[.rst:
FindSQLite3
-------------

Find the SQLite3 includes and library.

Result Variables
^^^^^^^^^^^^^^^^
This will define the following variables:

``SQLite3_INCLUDE_DIRS``
  where to find sqlite3.h, etc.
``SQLite3_LIBRARIES``
  the libraries to link against to use SQLite3.
``SQLite3_VERSION``
  version of the SQLite3 library found.
``SQLite3_FOUND``
  TRUE if found.
``SQLite3_LIB_NAMES``
  name of the libraries without path.

#]=======================================================================]
if(NOT DEFINED SQLite3_ROOT)
    message("SQLite_ROOT not defined")
endif()

if(DEFINED SQLite3_ROOT AND NOT IS_ABSOLUTE ${SQLite3_ROOT})
    set(SQLite3_ROOT "${CMAKE_SOURCE_DIR}/${SQLite3_ROOT}")
endif()

# Look for the necessary header
find_path(SQLite3_INCLUDE_DIR NAMES sqlite3.h
          PATHS ${SQLite3_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR}
          CMAKE_FIND_ROOT_PATH_BOTH)

# Look for the necessary library
find_library(SQLite3_LIBRARY NAMES sqlite3 sqlite
             PATHS ${SQLite3_ROOT}
             PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR}
             CMAKE_FIND_ROOT_PATH_BOTH)

# Extract version information from the header file
if(SQLite3_INCLUDE_DIR)
  file(STRINGS ${SQLite3_INCLUDE_DIR}/sqlite3.h _ver_line
      REGEX "^#define SQLITE_VERSION  *\"[0-9]+\\.[0-9]+\\.[0-9]+\""
      LIMIT_COUNT 1)
  string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+"
      SQLite3_VERSION "${_ver_line}")
  unset(_ver_line)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(${CMAKE_FIND_PACKAGE_NAME}
    REQUIRED_VARS SQLite3_LIBRARY
    VERSION_VAR SQLite3_VERSION)

# Create the imported target
get_property(MAKE_ROLE GLOBAL PROPERTY CMAKE_ROLE)

if(${CMAKE_FIND_PACKAGE_NAME}_FOUND AND NOT ${MAKE_ROLE} STREQUAL "SCRIPT")
  set(SQLite3_INCLUDE_DIRS ${SQLite3_INCLUDE_DIR})
  set(SQLite3_LIBRARIES ${SQLite3_LIBRARY})
  get_filename_component(SQLite3_LIB_NAMES ${SQLite3_LIBRARY} NAME)

  # Avoid redefining the target
  if(NOT TARGET SQLite3::SQLite3)
    # Define the imported target
    add_library(SQLite3::SQLite3 SHARED IMPORTED GLOBAL)

    set_target_properties(SQLite3::SQLite3 PROPERTIES
        IMPORTED_LOCATION "${SQLite3_LIBRARIES}")
  endif()

endif()

mark_as_advanced(SQLite3_INCLUDE_DIR SQLite3_LIBRARY SQLite3_FOUND SQLite3_LIB_NAMES)