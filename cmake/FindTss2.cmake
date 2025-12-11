#[=======================================================================[.rst:
FindTSS2
-------------

Find the TSS2 includes and library.

Result Variables
^^^^^^^^^^^^^^^^
This will define the following variables:

``Tss2_FOUND``
  True if the system has the TSS2 library.
``TSS2_INCLUDE_DIRS``
  TSS2 library include path.
``TSS2_LIBRARIES``
  TSS2 libraries fullname.

#]=======================================================================]
if(NOT DEFINED TSS2_ROOT)
    message(FATAL_ERROR "-DTSS2_ROOT=<TSS2 export path> missing")
endif()

if(NOT IS_ABSOLUTE ${TSS2_ROOT})
    set(TSS2_ROOT "${CMAKE_SOURCE_DIR}/${TSS2_ROOT}")
endif()

# Look for the necessary header
find_path(TSS2_INCLUDE_DIR tss2_tcti.h
          PATHS ${TSS2_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR}
                        usr/${CMAKE_INSTALL_INCLUDEDIR}/tss2
                        ${CMAKE_INSTALL_INCLUDEDIR}
                        ${CMAKE_INSTALL_INCLUDEDIR}/tss2
          CMAKE_FIND_ROOT_PATH_BOTH)

# Look for the necessary libraries
find_library(TSS2_MU_LIBRARY NAMES tss2-mu
             PATHS ${TSS2_ROOT}
             PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR}
             CMAKE_FIND_ROOT_PATH_BOTH)
find_library(TSS2_RC_LIBRARY NAMES tss2-rc
             PATHS ${TSS2_ROOT}
             PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR}
             CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  TSS2_RC_LIBRARY TSS2_MU_LIBRARY TSS2_INCLUDE_DIR)

# Create the imported target
if(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
  get_filename_component(TSS2_INCLUDE_DIRS ${TSS2_INCLUDE_DIR} DIRECTORY)
  list(APPEND TSS2_LIBRARIES ${TSS2_RC_LIBRARY} ${TSS2_MU_LIBRARY})

  # Avoid redefining the target
  if(NOT TARGET Tss2::Mu)
        # Define the imported target
        add_library(Tss2::Mu SHARED IMPORTED GLOBAL)

        set_target_properties(Tss2::Mu PROPERTIES
            IMPORTED_LOCATION "${TSS2_MU_LIBRARY}")
  endif()
  if(NOT TARGET Tss2::Rc)
        # Define the imported target
        add_library(Tss2::Rc SHARED IMPORTED GLOBAL)

        set_target_properties(Tss2::Rc PROPERTIES
            IMPORTED_LOCATION "${TSS2_RC_LIBRARY}")
  endif()

endif()

mark_as_advanced(TSS2_INCLUDE_DIR TSS2_MU_LIBRARY TSS2_RC_LIBRARY)
