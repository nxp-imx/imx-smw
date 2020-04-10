set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm32)

# Check the process is try the compilation
# if yes, compiler already defined so return
get_property(_IN_TC GLOBAL PROPERTY IN_TRY_COMPILE)
if(_IN_TC)
    return()
endif()

# https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-a/downloads

# Set the default aarch32 Cross-compiler toolchain
if(NOT TOOLCHAIN_NAME)
    set(TOOLCHAIN_NAME "arm-none-linux-gnueabihf")
    set(TOOLCHAIN_VERSION "9.2-2019.12" CACHE STRING "Default Toolchain Version")
    set(TOOLCHAIN_HASH "SHA256=51bbaf22a4d3e7a393264c4ef1e45566701c516274dde19c4892c911caa85617")
    set(TOOLCHAIN_SERVER "https://developer.arm.com/-/media/Files/downloads/gnu-a/")
    set(TOOLCHAIN_URL ${TOOLCHAIN_SERVER}${TOOLCHAIN_VERSION}/binrel/)
endif()

# Define the toolchain name
include(${CMAKE_SOURCE_DIR}/scripts/common_toolchain.cmake)
