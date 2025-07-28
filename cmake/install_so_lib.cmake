
function(extract_so_version LIB_FILENAME OUT_MAJOR OUT_MINOR OUT_PATCH)
  execute_process(
      COMMAND readlink -f ${LIB_FILENAME}
      OUTPUT_VARIABLE REAL_LIB_NAME
      OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  # Extract major, minor, patch
  string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" LIB_VERSION ${REAL_LIB_NAME})

  if(NOT LIB_VERSION)
    string(REGEX MATCH "[0-9]+\\.[0-9]+" LIB_VERSION ${REAL_LIB_NAME})

    if(NOT LIB_VERSION)
      string(REGEX MATCH "[0-9]+" LIB_VERSION ${REAL_LIB_NAME})
    else()
      # Extract minor (remove leading dot)
      string(REGEX MATCH "\\.[0-9]+" LIB_VERSION_MINOR_TMP ${LIB_VERSION})
      string(SUBSTRING ${LIB_VERSION_MINOR_TMP} 1 -1 LIB_VERSION_MINOR)
    endif()
 else()
    # Extract minor (remove leading dot)
    string(REGEX MATCH "\\.[0-9]+" LIB_VERSION_MINOR_TMP ${LIB_VERSION})
    string(SUBSTRING ${LIB_VERSION_MINOR_TMP} 1 -1 LIB_VERSION_MINOR)

    # Extract patch (remove leading dot)
    string(REGEX MATCH "\\.[0-9]+$" LIB_VERSION_PATCH_TMP ${LIB_VERSION})
    string(SUBSTRING ${LIB_VERSION_PATCH_TMP} 1 -1 LIB_VERSION_PATCH)
  endif()

  # Extract major
  string(REGEX MATCH "^[0-9]+" LIB_VERSION_MAJOR ${LIB_VERSION})

  # Return values
  set(${OUT_MAJOR} ${LIB_VERSION_MAJOR} PARENT_SCOPE)
  set(${OUT_MINOR} ${LIB_VERSION_MINOR} PARENT_SCOPE)
  set(${OUT_PATCH} ${LIB_VERSION_PATCH} PARENT_SCOPE)
endfunction()

function(install_so_lib LIB_FILENAMES INSTALL_DIR)
  foreach(LIB_FILENAME IN LISTS LIB_FILENAMES)
    extract_so_version(${LIB_FILENAME} MAJOR MINOR PATCH)

    if (PATCH MATCHES "^[0-9]+$")
      set(LIB_REAL "${LIB_FILENAME}.${MAJOR}.${MINOR}.${PATCH}")
      set(LIB_LINK_MINOR "${LIB_FILENAME}.${MAJOR}.${MINOR}")
      set(LIB_LINK_MAJOR "${LIB_FILENAME}.${MAJOR}")
    elseif(MINOR MATCHES "^[0-9]+$")
      set(LIB_REAL "${LIB_FILENAME}.${MAJOR}.${MINOR}")
      set(LIB_LINK_MAJOR "${LIB_FILENAME}.${MAJOR}")
    elseif(MAJOR MATCHES "^[0-9]+$")
      set(LIB_REAL "${LIB_FILENAME}.${MAJOR}")
    endif()

    if(DEFINED LIB_REAL)
      # Install the real library file
      install(FILES ${LIB_REAL} DESTINATION ${INSTALL_DIR})
    endif()

    if(DEFINED LIB_LINK_MAJOR AND EXISTS ${LIB_LINK_MAJOR})
      install(FILES ${LIB_LINK_MAJOR} DESTINATION ${INSTALL_DIR})
    endif()

    if(DEFINED LIB_LINK_MINOR AND EXISTS ${LIB_LINK_MINOR})
      install(FILES ${LIB_LINK_MINOR} DESTINATION ${INSTALL_DIR})
    endif()
  endforeach()
endfunction()
