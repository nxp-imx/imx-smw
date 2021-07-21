set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:config> PARENT_SCOPE)

add_library(config OBJECT "")
set_target_properties(config PROPERTIES C_VISIBILITY_PRESET hidden)
target_sources(config PRIVATE
               entry.c
               parser.c
               database.c
               config.c
               tag.c
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c>
               $<$<BOOL:${ENABLE_HASH}>:hash.c>
               $<$<BOOL:${ENABLE_SIGN_VERIFY}>:sign_verify.c>
               $<$<BOOL:${ENABLE_HMAC}>:hmac.c>
               $<$<BOOL:${ENABLE_RNG}>:rng.c>
               $<$<BOOL:${ENABLE_CIPHER}>:cipher.c>)
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND VERBOSE AND NOT VERBOSE EQUAL 0)
target_sources(config PRIVATE
               database_debug.c
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr_debug.c>
               $<$<BOOL:${ENABLE_HASH}>:hash_debug.c>
               $<$<BOOL:${ENABLE_SIGN_VERIFY}>:sign_verify_debug.c>
               $<$<BOOL:${ENABLE_HMAC}>:hmac_debug.c>
               $<$<BOOL:${ENABLE_RNG}>:rng_debug.c>
               $<$<BOOL:${ENABLE_CIPHER}>:cipher_debug.c>)
endif()
target_include_directories(config PRIVATE ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/subsystems_apis.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/subsystems_apis.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/operations_apis.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/operations_apis.h)
