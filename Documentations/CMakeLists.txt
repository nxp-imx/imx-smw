cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})

function(find_python_modules all_found inst_mod)
  set(${all_found} 0 PARENT_SCOPE)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)

  file(STRINGS ${DOC_API_SOURCE_DIR}/requirements.txt py_modules)

  foreach(mod ${py_modules})
    message(STATUS "Check if python3 module ${mod} installed")
    execute_process(COMMAND ${Python3_EXECUTABLE} -m pip show ${mod}
                    OUTPUT_QUIET
                    RESULT_VARIABLE res)
    if (NOT ${res} EQUAL 0)
      if (${inst_mod})
        execute_process(COMMAND ${Python3_EXECUTABLE} -m pip install ${mod}
                        OUTPUT_QUIET
                        RESULT_VARIABLE res)
        if(NOT ${res} EQUAL 0)
          message(FATAL_ERROR "Cannot install python3 ${mod} module: ${res}")
        endif()
      else()
        return()
      endif()
    endif()
  endforeach(mod)

  set(${all_found} 1 PARENT_SCOPE)
endfunction()

if(NOT DEFINED FORMAT)
    return()
endif()

message(STATUS "Documentations")

set(DOC_API_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/API/source)
set(DOC_API_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/API)

set(BUILD_DOC_DEFINITIONS
    -DBUILD_DOC_SOURCE_DIR=${DOC_API_SOURCE_DIR}
    -DBUILD_DOC_OUTPUT_DIR=${DOC_API_OUTPUT_DIR})

if(${FORMAT} STREQUAL "html" OR
   ${FORMAT} STREQUAL "all")
    list(APPEND BUILD_DOC_BUILDER html)
endif()

if(${FORMAT} STREQUAL "pdf" OR ${FORMAT} STREQUAL "all")
    find_package(Latexmk)
    if(NOT LATEXMK_FOUND)
        message(WARNING
                "latexmk is required to build pdf documentation\n"
                "Please run commands:\n"
                "    sudo apt install texlive-latex-extra\n"
                "    sudo apt install latexmk\n")
        if(${FORMAT} STREQUAL "pdf")
            return()
        endif()
    else()
        list(APPEND BUILD_DOC_BUILDER latexpdf)
    endif()
endif()

string(REPLACE ";" " " BUILD_DOC_BUILDER "${BUILD_DOC_BUILDER}")

set(PROJECT_COPYRIGHT "2021-2023 - NXP - Non-Confidential")
configure_file(${DOC_API_SOURCE_DIR}/conf.py.in
               ${DOC_API_SOURCE_DIR}/conf.py)

find_python_modules(ALL_PY_MOD_FOUND FALSE)
if(${ALL_PY_MOD_FOUND} EQUAL 0)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)

  if(NOT EXISTS "${CMAKE_BINARY_DIR}/venv")
    execute_process(COMMAND ${Python3_EXECUTABLE} -m venv venv
                    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
                    RESULT_VARIABLE res)
    if(NOT ${res} EQUAL 0)
      message(FATAL_ERROR "Unable to create python3 virtual environment ${res}")
    endif()
  endif()

  SET(ENV{VIRTUAL_ENV} "${CMAKE_BINARY_DIR}/venv")
  SET(Python3_FIND_VIRTUALENV FIRST)
  UNSET(Python3_EXECUTABLE)

  find_python_modules(ALL_PY_MOD_FOUND TRUE)

  UNSET(ENV{VIRTUAL_ENV})
endif()

add_custom_target(docs
                  COMMAND ${CMAKE_COMMAND} -DBUILD_DOC_BUILDER=${BUILD_DOC_BUILDER}
                      ${BUILD_DOC_DEFINITIONS} -DCMAKE_SCRIPT_PATH=${CMAKE_SOURCE_DIR}
                      -DCMAKE_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}
                      -P ${CMAKE_SOURCE_DIR}/scripts/build_doc.cmake
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                  VERBATIM)
