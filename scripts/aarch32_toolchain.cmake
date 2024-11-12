set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm32)
set(CMAKE_SIZEOF_VOID_P 32)

# Check the process is try the compilation
# if yes, compiler already defined so return
get_property(_IN_TC GLOBAL PROPERTY IN_TRY_COMPILE)
if(_IN_TC)
    return()
endif()

# https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads

# Set the default aarch32 Cross-compiler toolchain
if(NOT TOOLCHAIN_NAME)
    set(TOOLCHAIN_NAME "arm-none-linux-gnueabihf")
    set(TOOLCHAIN_VERSION "11.2-2022.02" CACHE STRING "Default Toolchain Version")
    set(TOOLCHAIN_HASH "SHA256=c254f7199261fe76c32ef42187502839bda7efad0a66646cf739d074eff45fad")
    set(TOOLCHAIN_SERVER "https://developer.arm.com/-/media/Files/downloads/gnu/")
    set(TOOLCHAIN_URL ${TOOLCHAIN_SERVER}${TOOLCHAIN_VERSION}/binrel/)
endif()

# Define the toolchain name
include(${CMAKE_CURRENT_LIST_DIR}/common_toolchain.cmake)
