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
# Look for the necessary header
find_path(SQLite3_INCLUDE_DIR NAMES sqlite3.h)
mark_as_advanced(SQLite3_INCLUDE_DIR)

# Look for the necessary library
find_library(SQLite3_LIBRARY NAMES sqlite3 sqlite)
mark_as_advanced(SQLite3_LIBRARY)

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
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME}
    REQUIRED_VARS SQLite3_INCLUDE_DIR SQLite3_LIBRARY
    VERSION_VAR SQLite3_VERSION)
mark_as_advanced(SQLite3_FOUND)

# Create the imported target
if(SQLite3_FOUND)
  set(SQLite3_INCLUDE_DIRS ${SQLite3_INCLUDE_DIR})
  set(SQLite3_LIBRARIES ${SQLite3_LIBRARY})
  get_filename_component(SQLite3_LIB_NAMES ${SQLite3_LIBRARY} NAME)
endif()
