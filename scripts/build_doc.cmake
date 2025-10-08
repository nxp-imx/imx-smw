list(APPEND CMAKE_MODULE_PATH PATHS ${CMAKE_SCRIPT_PATH}/cmake)

if(EXISTS "${CMAKE_BINARY_DIR}/venv")
  set(ENV{VIRTUAL_ENV} "${CMAKE_BINARY_DIR}/venv")
  set(Python3_FIND_VIRTUALENV FIRST)
  unset(Python3_EXECUTABLE)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

find_package(Sphinx REQUIRED)
find_package(Kerneldoc REQUIRED)
set(ENV{srctree} ${BUILD_DOC_PRJ_DIR})
set(ENV{PYTHONDONTWRITEBYTECODE} 1)

string(REPLACE " " ";" BUILD_DOC_BUILDER "${BUILD_DOC_BUILDER}")

foreach(BUILDER ${BUILD_DOC_BUILDER})
    message(STATUS "BUILDER: ${BUILDER}")
    execute_process(COMMAND
                    ${SPHINX_EXECUTABLE} -M ${BUILDER}
                    ${BUILD_DOC_SOURCE_DIR} ${BUILD_DOC_OUTPUT_DIR} -T 
                    COMMAND_ECHO STDOUT)

endforeach()

unset(ENV{srctree})
unset(ENV{PYTHONDONTWRITEBYTECODE})

unset(ENV{VIRTUAL_ENV})
unset(Python3_EXECUTABLE)