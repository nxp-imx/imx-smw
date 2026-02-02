# This file is used when building SMW as a Zephyr external module.

include(CMakeDependentOption)

# Declare a Zephyr module library
zephyr_library()

project("${ZEPHYR_CURRENT_LIBRARY}" VERSION 1.0 LANGUAGES C)

set(OS zephyr)
set(BUILD_ZEPHYR 1)

message(STATUS "Building SMW module for OS=${OS}")

# Add include directories
zephyr_include_directories(
        ${ZEPHYR_CURRENT_MODULE_DIR}/public
        ${ZEPHYR_CURRENT_MODULE_DIR}/inc
)

set(CMAKE_LOCAL_MODULE_PATH "${ZEPHYR_CURRENT_MODULE_DIR}/cmake")
set(CMAKE_MODULE_PATH ${CMAKE_LOCAL_MODULE_PATH} ${CMAKE_MODULE_PATH})

zephyr_library_compile_options(-Wno-incompatible-pointer-types -Wno-address-of-packed-member)

# Export compile definitions based on Kconfig to preserve legacy macros
cmake_dependent_option(ENABLE_KEYMGR_MODULE "Link the Key manager" ON "CONFIG_ENABLE_KEYMGR_MODULE" OFF)
cmake_dependent_option(ENABLE_HASH "Enable Hash" ON "CONFIG_ENABLE_HASH" OFF)
cmake_dependent_option(ENABLE_SIGN_VERIFY "Enable Sign and Verify" ON "CONFIG_ENABLE_SIGN_VERIFY" OFF)
cmake_dependent_option(ENABLE_CIPHER "Enable Cipher" ON "CONFIG_ENABLE_CIPHER" OFF)
cmake_dependent_option(ENABLE_MAC "Enable MAC" ON "CONFIG_ENABLE_MAC" OFF)
cmake_dependent_option(ENABLE_AEAD "Enable authenticated encryption" ON "CONFIG_ENABLE_AEAD" OFF)
cmake_dependent_option(ENABLE_RNG "Enable Random number generator" ON "CONFIG_ENABLE_RNG" OFF)
cmake_dependent_option(ENABLE_TLS "Enable TLS features" OFF "CONFIG_ENABLE_TLS" OFF)
cmake_dependent_option(ENABLE_ASYMMETRIC_ENCRYPTION "Enable asymmetric encryption" ON "CONFIG_ENABLE_ASYMMETRIC_ENCRYPTION" OFF)
cmake_dependent_option(ENABLE_DEVMGR_MODULE "Enable device manager module" ON "CONFIG_ENABLE_DEVMGR_MODULE" OFF)
cmake_dependent_option(ENABLE_DEVICE_ATTESTATION "Enable device attestation" ON "CONFIG_ENABLE_DEVICE_ATTESTATION" OFF)
cmake_dependent_option(ENABLE_DEVICE_LIFECYCLE "Enable device lifecycle" ON "CONFIG_ENABLE_DEVICE_LIFECYCLE" OFF)
cmake_dependent_option(ENABLE_DEVICE_REPROVISION "Enable device storage reprovisioning" ON "CONFIG_ENABLE_DEVICE_REPROVISION" OFF)
cmake_dependent_option(ENABLE_STORAGE_MODULE "Enable storage module" ON "CONFIG_ENABLE_STORAGE_MODULE" OFF)
cmake_dependent_option(ENABLE_OBJECT_MODULE "Enable object module" ON "CONFIG_ENABLE_OBJECT_MODULE" OFF)

# Add OS abstraction layer
add_subdirectory(${ZEPHYR_CURRENT_MODULE_DIR}/osal/${OS} ${CMAKE_CURRENT_BINARY_DIR}/osal_${OS})

if(NOT CONFIG_SMW_LOG_LEVEL MATCHES "^[0-9]$")
        message(FATAL_ERROR "SMW_LOG_LEVEL must be an integer")
endif()

if(NOT CONFIG_SMW_LOG_LEVEL EQUAL 0)
        add_compile_definitions(ENABLE_TRACE)
endif()

add_subdirectory(${ZEPHYR_CURRENT_MODULE_DIR}/core ${CMAKE_CURRENT_BINARY_DIR}/core)
