if(NOT BUILD_ZEPHYR)
  set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:config> PARENT_SCOPE)

  add_library(config OBJECT "")
  set_target_properties(config PROPERTIES C_VISIBILITY_PRESET hidden)
endif()

include(add_target_sources)

add_private_sources(config
  entry.c
  parser.c
  database.c
  config.c
  tag.c
  hash_parser.c
  mac_parser.c
  cipher_parser.c)

add_private_sources_ifdef(config ENABLE_KEYMGR_MODULE keymgr.c)
add_private_sources_ifdef(config ENABLE_HASH hash.c)
add_private_sources_ifdef(config ENABLE_SIGN_VERIFY sign_verify.c)
add_private_sources_ifdef(config ENABLE_RNG rng.c)
add_private_sources_ifdef(config ENABLE_CIPHER cipher.c)
add_private_sources_ifdef(config ENABLE_MAC mac.c)
add_private_sources_ifdef(config ENABLE_PSA_DEFAULT_ALT parser_psa_alt.c)
add_private_sources_ifdef(config ENABLE_DEVMGR_MODULE device.c)
add_private_sources_ifdef(config ENABLE_STORAGE_MODULE storage.c)
add_private_sources_ifdef(config ENABLE_AEAD aead.c)
add_private_sources_ifdef(config ENABLE_ASYMMETRIC_ENCRYPTION asymmetric_encryption.c)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND VERBOSE AND NOT VERBOSE EQUAL 0)
  add_private_sources(config database_debug.c)

  add_private_sources_ifdef(config ENABLE_KEYMGR_MODULE keymgr_debug.c)
  add_private_sources_ifdef(config ENABLE_HASH hash_debug.c)
  add_private_sources_ifdef(config ENABLE_SIGN_VERIFY sign_verify_debug.c)
  add_private_sources_ifdef(config ENABLE_RNG rng_debug.c)
  add_private_sources_ifdef(config ENABLE_CIPHER cipher_debug.c)
  add_private_sources_ifdef(config ENABLE_MAC mac_debug.c)
  add_private_sources_ifdef(config ENABLE_STORAGE_MODULE storage_debug.c)
  add_private_sources_ifdef(config ENABLE_AEAD aead_debug.c)
  add_private_sources_ifdef(config ENABLE_ASYMMETRIC_ENCRYPTION asymmetric_encryption_debug.c)
endif()

add_private_directories(config ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/subsystems_apis.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/subsystems_apis.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/operations_apis.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/operations_apis.h)
