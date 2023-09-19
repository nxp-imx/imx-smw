list(APPEND CMAKE_MODULE_PATH PATHS ${CMAKE_SCRIPT_PATH}/cmake)

if(EXISTS "${CMAKE_BINARY_DIR}/venv")
  SET(ENV{VIRTUAL_ENV} "${CMAKE_BINARY_DIR}/venv")
  SET(Python3_FIND_VIRTUALENV FIRST)
  UNSET(Python3_EXECUTABLE)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

find_package(Sphinx REQUIRED)
find_package(Kerneldoc REQUIRED)

string(REPLACE " " ";" BUILD_DOC_BUILDER "${BUILD_DOC_BUILDER}")

foreach(BUILDER ${BUILD_DOC_BUILDER})
    message(STATUS "BUILDER: ${BUILDER}")
    execute_process(COMMAND
                    ${SPHINX_EXECUTABLE} -M ${BUILDER}
                    ${BUILD_DOC_SOURCE_DIR} ${BUILD_DOC_OUTPUT_DIR})
endforeach()

UNSET(ENV{VIRTUAL_ENV})
UNSET(Python3_EXECUTABLE)