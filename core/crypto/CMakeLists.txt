set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:crypto> PARENT_SCOPE)

if(ENABLE_HASH)
add_operation(HASH)
endif()

if(ENABLE_SIGN_VERIFY)
add_operation(SIGN)
add_operation(VERIFY)
endif()

add_library(crypto OBJECT "" ${INCLUDE_DIR})
target_sources(crypto PRIVATE
               crypto_weak.c
               $<$<BOOL:${ENABLE_HASH}>:hash.c>
               $<$<BOOL:${ENABLE_SIGN_VERIFY}>:sign_verify.c>)
target_include_directories(crypto PRIVATE ${INCLUDE_DIR})
