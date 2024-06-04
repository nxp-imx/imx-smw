if(NOT DEFINED SECO_ROOT)
    message(STATUS "SECO not enabled")
    return()
endif()

find_package(Seco REQUIRED)

#
# Add SECO subsystem
#
add_subsystem(seco)

set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:seco> PARENT_SCOPE)

message(STATUS "    Seco Libraries: ${SECO_LIBRARIES}")
message(STATUS "    Seco Headers  : ${SECO_INCLUDE_DIRS}")

add_library(seco OBJECT "")
set_target_properties(seco PROPERTIES C_VISIBILITY_PRESET hidden)

if (ENABLE_CIPHER OR ENABLE_AEAD)
    set(ENABLE_CONTEXT ON)
endif()

target_sources(seco PRIVATE
               entry.c
               $<$<BOOL:${ENABLE_AEAD}>:aead.c>
               $<$<BOOL:${ENABLE_CONTEXT}>:operation_context.c>
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c keymgr_derive.c key_group.c>
               $<$<BOOL:${ENABLE_HASH}>:hash.c>
               $<$<BOOL:${ENABLE_MAC}>:mac.c>
               $<$<BOOL:${ENABLE_SIGN_VERIFY}>:sign_verify.c>
               $<$<BOOL:${ENABLE_RNG}>:rng.c>
               $<$<BOOL:${ENABLE_CIPHER}>:cipher.c>
               $<$<AND:$<BOOL:${ENABLE_TLS12}>,$<BOOL:${ENABLE_KEYMGR_MODULE}>>:keymgr_derive_tls12.c>
               $<$<AND:$<BOOL:${ENABLE_TLS12}>,$<BOOL:${ENABLE_SIGN_VERIFY}>>:sign_verify_tls12.c>
               $<$<BOOL:${ENABLE_STORAGE_MODULE}>:storage.c>)

target_include_directories(seco PRIVATE ${INCLUDE_DIR}
                           ${SECO_INCLUDE_DIRS})

set(EXT_LIBS ${EXT_LIBS} ${SECO_LIBRARIES} PARENT_SCOPE)
