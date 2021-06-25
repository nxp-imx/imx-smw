#
# Install sphinx
#
list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
find_package(Sphinx)

if(SPHINX_FOUND)
    message(STATUS "sphinx already installed")
    return()
endif()

message(STATUS "Installing sphinx")
execute_process(COMMAND python3 -m pip install "sphinx"
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot install sphinx ${res}")
endif()
