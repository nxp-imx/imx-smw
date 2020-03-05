set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm64)

# Check the process is try the compilation
# if yes, compiler already defined so return
get_property(_IN_TC GLOBAL PROPERTY IN_TRY_COMPILE)
if(_IN_TC)
    return()
endif()

# Set the default aarch64 Cross-compiler toolchain
if(NOT TOOLCHAIN_NAME)
    set(TOOLCHAIN_NAME "aarch64-none-linux-gnu")
    set(TOOLCHAIN_VERSION "9.2-2019.12" CACHE STRING "Default Toolchain Version")
    set(TOOLCHAIN_SERVER "https://developer.arm.com/-/media/Files/downloads/gnu-a/")
    set(TOOLCHAIN_WGET ${TOOLCHAIN_SERVER}${TOOLCHAIN_VERSION}/binrel/)
endif()

# Define the toolchain name
include(${CMAKE_SOURCE_DIR}/scripts/common_toolchain.cmake)
