if(ENABLE_HASH)
    add_operation(HASH)
    add_operation(HASH_MULTI_PART)
endif()

if(ENABLE_SIGN_VERIFY)
    add_operation(SIGN)
    add_operation(VERIFY)
    add_operation(SIGN_MULTI_PART)
    add_operation(VERIFY_MULTI_PART)
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

if(ENABLE_AEAD)
    add_operation(AEAD)
    add_operation(AEAD_MULTI_PART)
    add_operation_implicit(AEAD_UPDATE_AAD)
endif()

if(ENABLE_ASYMMETRIC_ENCRYPTION)
    add_operation(ASYMM_ENCRYPT)
    add_operation(ASYMM_DECRYPT)
endif()

#
# If at least one of the operation that supports MULTI_PART is enabled, context
# features are enabled
#
if(ENABLE_CIPHER OR ENABLE_AEAD OR ENABLE_HASH OR ENABLE_TLS OR
    ENABLE_SIGN_VERIFY)
    set(ENABLE_CONTEXT ON)
endif()

if(NOT BUILD_ZEPHYR)
    set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:crypto> PARENT_SCOPE)

    add_library(crypto OBJECT "")
endif()

include(add_target_sources)

add_private_sources(crypto crypto_weak.c)

add_private_sources_ifdef(crypto ENABLE_HASH hash.c)
add_private_sources_ifdef(crypto ENABLE_SIGN_VERIFY sign_verify.c)
add_private_sources_ifdef(crypto ENABLE_MAC mac.c)
add_private_sources_ifdef(crypto ENABLE_RNG rng.c)
add_private_sources_ifdef(crypto ENABLE_CIPHER cipher.c)
add_private_sources_ifdef(crypto ENABLE_CONTEXT operation_context.c)
add_private_sources_ifdef(crypto ENABLE_AEAD aead.c)
add_private_sources_ifdef(crypto ENABLE_ASYMMETRIC_ENCRYPTION asymmetric_encryption.c)

add_private_directories(crypto ${INCLUDE_DIR})
