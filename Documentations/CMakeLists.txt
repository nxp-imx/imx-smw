cmake_minimum_required(VERSION 3.5)

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

set(PROJECT_COPYRIGHT "2021 - NXP - Non-Confidential")
configure_file(${DOC_API_SOURCE_DIR}/conf.py.in
               ${DOC_API_SOURCE_DIR}/conf.py)

message(STATUS "Installing requirements for API documentation")
execute_process(COMMAND python3 -m pip install -r ${DOC_API_SOURCE_DIR}/requirements.txt
                OUTPUT_QUIET
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot install requirements for API documentation ${res}")
endif()

add_custom_target(docs
                  ${CMAKE_COMMAND} -DBUILD_DOC_BUILDER=${BUILD_DOC_BUILDER}
                      ${BUILD_DOC_DEFINITIONS}
                      -P ${CMAKE_SOURCE_DIR}/scripts/build_doc.cmake
                  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                  VERBATIM)
