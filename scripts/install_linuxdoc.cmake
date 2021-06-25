#
# Install linuxdoc
#
list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
find_package(Kerneldoc)

if(KERNELDOC_FOUND)
    message(STATUS "linuxdoc already installed")
    return()
endif()

message(STATUS "Installing linuxdoc")
execute_process(COMMAND python3 -m pip install "linuxdoc"
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot install linuxdoc ${res}")
endif()
