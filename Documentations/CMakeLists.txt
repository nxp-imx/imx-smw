cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})

function(find_python_modules all_found inst_mod)
  set(${all_found} FALSE PARENT_SCOPE)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)

  file(STRINGS ${DOC_USER_MANUAL_SOURCE_DIR}/requirements.txt py_modules)

  foreach(mod_spec ${py_modules})
    # Skip empty lines and comments
    string(STRIP "${mod_spec}" mod_spec)
    if("${mod_spec}" STREQUAL "" OR "${mod_spec}" MATCHES "^#")
      continue()
    endif()

    # Parse module name and version specifier (e.g., "sphinx==7.2.6" or "sphinx>=7.2.6")
    string(REGEX MATCH "^([a-zA-Z0-9_-]+)([=<>!]+)(.+)$" match "${mod_spec}")
    if(match)
      set(mod_name "${CMAKE_MATCH_1}")
      set(version_op "${CMAKE_MATCH_2}")
      set(required_version "${CMAKE_MATCH_3}")
    else()
      # No version specified, just module name
      set(mod_name "${mod_spec}")
      set(version_op "")
      set(required_version "")
    endif()

    message(STATUS "Check if python3 module ${mod_name} installed")

    # Check if module is installed and get its version
    execute_process(COMMAND ${Python3_EXECUTABLE} -m pip show ${mod_name}
                    OUTPUT_VARIABLE pip_output
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    RESULT_VARIABLE res)

    if(${res} EQUAL 0)
      # Module is installed, extract version
      string(REGEX MATCH "Version: ([^\n]+)" version_match "${pip_output}")
      if(version_match)
        set(installed_version "${CMAKE_MATCH_1}")
        message(STATUS "  Found ${mod_name} version ${installed_version}")

        # Check version compatibility if version was specified
        if(NOT "${version_op}" STREQUAL "")
          execute_process(COMMAND ${Python3_EXECUTABLE} -c
                          "from packaging import version; import sys; sys.exit(0 if version.parse('${installed_version}') ${version_op} version.parse('${required_version}') else 1)"
                          RESULT_VARIABLE version_check
                          ERROR_QUIET)

          if(NOT ${version_check} EQUAL 0)
            message(STATUS "  Version mismatch: ${installed_version} does not satisfy ${version_op}${required_version}")
            set(res 1)
          else()
            message(STATUS "  Version ${installed_version} satisfies ${version_op} ${required_version}")
          endif()
        endif()
      endif()
    else()
      message(STATUS "  Module ${mod_name} not found")
    endif()

    # Install or reinstall if needed
    if(NOT ${res} EQUAL 0)
      if(${inst_mod})
        message(STATUS "  Installing ${mod_spec}")
        execute_process(COMMAND ${Python3_EXECUTABLE} -m pip install "${mod_spec}"
                        OUTPUT_QUIET
                        RESULT_VARIABLE res)
        if(NOT ${res} EQUAL 0)
          message(FATAL_ERROR "Cannot install python3 module ${mod_spec}: ${res}")
        endif()
        message(STATUS "  Successfully installed ${mod_spec}")
      else()
        return()
      endif()
    endif()
  endforeach()

  set(${all_found} TRUE PARENT_SCOPE)
endfunction()

if(DEFINED FORMAT)
   message(WARNING "FORMAT is deprecated, use DOC_FORMAT instead")
   set(DOC_FORMAT ${FORMAT})
endif()

if(NOT DEFINED DOC_FORMAT)
    set(DOC_FORMAT "all")
endif()

message(STATUS "Documentations")

set(DOC_USER_MANUAL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/user_manual/source)
set(DOC_USER_MANUAL_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/user_manual)

set(BUILD_DOC_DEFINITIONS
    -DBUILD_DOC_SOURCE_DIR=${DOC_USER_MANUAL_SOURCE_DIR}
    -DBUILD_DOC_OUTPUT_DIR=${DOC_USER_MANUAL_OUTPUT_DIR}
    -DBUILD_DOC_PRJ_DIR=${CMAKE_SOURCE_DIR})

if(${DOC_FORMAT} STREQUAL "html" OR ${DOC_FORMAT} STREQUAL "all")
    list(APPEND BUILD_DOC_BUILDER html)
endif()

if(${DOC_FORMAT} STREQUAL "xml" OR ${DOC_FORMAT} STREQUAL "all")
    list(APPEND BUILD_DOC_BUILDER xml)
endif()

if(DEFINED BUILD_DOC_BUILDER)
    string(REPLACE ";" " " BUILD_DOC_BUILDER "${BUILD_DOC_BUILDER}")
endif()

string(TIMESTAMP CURRENT_YEAR "%Y")
set(PROJECT_COPYRIGHT "2021-${CURRENT_YEAR} - NXP - Non-Confidential")
configure_file(${DOC_USER_MANUAL_SOURCE_DIR}/conf.py.in
               ${DOC_USER_MANUAL_SOURCE_DIR}/conf.py)

if(NOT EXISTS "${CMAKE_BINARY_DIR}/venv")
   find_python_modules(ALL_PY_MOD_FOUND FALSE)
endif()

if(NOT ALL_PY_MOD_FOUND)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)

  if(NOT EXISTS "${CMAKE_BINARY_DIR}/venv")
    execute_process(COMMAND ${Python3_EXECUTABLE} -m venv venv
                    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
                    RESULT_VARIABLE res)
    if(NOT ${res} EQUAL 0)
      message(FATAL_ERROR "Unable to create python3 virtual environment ${res}")
    endif()
  endif()

  set(ENV{VIRTUAL_ENV} "${CMAKE_BINARY_DIR}/venv")
  set(Python3_FIND_VIRTUALENV FIRST)
  unset(Python3_EXECUTABLE)

  find_python_modules(ALL_PY_MOD_FOUND TRUE)

  unset(ENV{VIRTUAL_ENV})
endif()

add_custom_target(docs
                  COMMAND ${CMAKE_COMMAND} -DBUILD_DOC_BUILDER=${BUILD_DOC_BUILDER}
                      ${BUILD_DOC_DEFINITIONS} -DCMAKE_SCRIPT_PATH=${CMAKE_SOURCE_DIR}
                      -DCMAKE_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}
                      -P ${CMAKE_SOURCE_DIR}/scripts/build_doc.cmake
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                  VERBATIM)
