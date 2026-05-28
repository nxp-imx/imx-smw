include(add_target_sources)

add_private_sources(config
        entry.c
        parser.c
        database_operation.c
        config.c
        tag.c
        hash_parser.c
        mac_parser.c
        cipher_parser.c)

add_private_sources_ifdef(config ENABLE_KEYMGR_MODULE dynamic/keymgr.c)
add_private_sources_ifdef(config ENABLE_HASH dynamic/hash.c)
add_private_sources_ifdef(config ENABLE_SIGN_VERIFY dynamic/sign_verify.c)
add_private_sources_ifdef(config ENABLE_RNG dynamic/rng.c)
add_private_sources_ifdef(config ENABLE_CIPHER dynamic/cipher.c)
add_private_sources_ifdef(config ENABLE_MAC dynamic/mac.c)
add_private_sources_ifdef(config ENABLE_PSA_DEFAULT_ALT dynamic/parser_psa_alt.c)
add_private_sources_ifdef(config ENABLE_DEVMGR_MODULE dynamic/device.c)
add_private_sources_ifdef(config ENABLE_STORAGE_MODULE dynamic/storage.c)
add_private_sources_ifdef(config ENABLE_AEAD dynamic/aead.c)
add_private_sources_ifdef(config ENABLE_ASYMMETRIC_ENCRYPTION dynamic/asymmetric_encryption.c)
add_private_sources_ifdef(config ENABLE_ELA dynamic/parse_enable_ela.c)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND VERBOSE AND NOT VERBOSE EQUAL 0)
        add_private_sources(config database_debug.c)

        add_private_sources_ifdef(config ENABLE_KEYMGR_MODULE dynamic/keymgr_debug.c)
        add_private_sources_ifdef(config ENABLE_HASH dynamic/hash_debug.c)
        add_private_sources_ifdef(config ENABLE_SIGN_VERIFY dynamic/sign_verify_debug.c)
        add_private_sources_ifdef(config ENABLE_RNG dynamic/rng_debug.c)
        add_private_sources_ifdef(config ENABLE_CIPHER dynamic/cipher_debug.c)
        add_private_sources_ifdef(config ENABLE_MAC dynamic/mac_debug.c)
        add_private_sources_ifdef(config ENABLE_STORAGE_MODULE dynamic/storage_debug.c)
        add_private_sources_ifdef(config ENABLE_AEAD dynamic/aead_debug.c)
        add_private_sources_ifdef(config ENABLE_ASYMMETRIC_ENCRYPTION dynamic/asymmetric_encryption_debug.c)
endif()

get_filename_component(CMAKE_PARENT_LIST_DIR ${CMAKE_PARENT_LIST_FILE} DIRECTORY)
get_filename_component(CMAKE_PARENT_LIST_DIR ${CMAKE_PARENT_LIST_DIR} DIRECTORY)

get_filename_component(CMAKE_PARENT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)

add_private_directories(config ${CMAKE_PARENT_LIST_DIR} ${INCLUDE_DIR} ${CMAKE_PARENT_BINARY_DIR})
