set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:crypto> PARENT_SCOPE)

if(ENABLE_HASH)
add_operation(HASH)
endif()

if(ENABLE_SIGN_VERIFY)
add_operation(SIGN)
add_operation(VERIFY)
endif()

if(ENABLE_HMAC)
add_operation(HMAC)
endif()

if(ENABLE_RNG)
add_operation(RNG)
endif()

if(ENABLE_CIPHER)
add_operation(CIPHER)
add_operation(CIPHER_MULTI_PART)
endif()

if(ENABLE_MAC)
add_operation(MAC)
endif()

#
# If at least one of the operation that supports MULTI_PART is enabled, context
# features are enabled
#
if (ENABLE_CIPHER)
set(ENABLE_CONTEXT ON)
endif()

add_library(crypto OBJECT "")
target_sources(crypto PRIVATE
               crypto_weak.c
               $<$<BOOL:${ENABLE_HASH}>:hash.c>
               $<$<BOOL:${ENABLE_SIGN_VERIFY}>:sign_verify.c>
               $<$<BOOL:${ENABLE_HMAC}>:hmac.c>
               $<$<BOOL:${ENABLE_RNG}>:rng.c>
               $<$<BOOL:${ENABLE_CIPHER}>:cipher.c>
               $<$<BOOL:${ENABLE_CONTEXT}>:operation_context.c>)
target_include_directories(crypto PRIVATE ${INCLUDE_DIR})
