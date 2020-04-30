set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:crypto> PARENT_SCOPE)

if(ENABLE_HASH)
add_operation(HASH)
endif()

add_library(crypto OBJECT "" ${INCLUDE_DIR})
target_sources(crypto PRIVATE
               crypto_weak.c
               $<$<BOOL:${ENABLE_HASH}>:hash.c>)
target_include_directories(crypto PRIVATE ${INCLUDE_DIR})
