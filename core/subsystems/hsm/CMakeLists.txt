if(NOT DEFINED SECO_ROOT)
    message(STATUS "HSM not enabled")
    return()
endif()

find_package(ZLIBLight REQUIRED)
find_package(Seco REQUIRED)

#
# Add HSM subsystem
#
add_subsystem(hsm)

set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:hsm> PARENT_SCOPE)

message(STATUS "    Seco Libraries: ${SECO_LIBRARIES}")
message(STATUS "    Seco Headers  : ${SECO_INCLUDE_DIRS}")
message(STATUS "    ZLIB Library  : ${ZLIB_LIBRARY}")
message(STATUS "    ZLIB Header   : ${ZLIB_INCLUDE_DIR}")

add_library(hsm OBJECT "")
set_target_properties(hsm PROPERTIES C_VISIBILITY_PRESET hidden)

target_sources(hsm PRIVATE
               entry.c common.h
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c keymgr_derive.c>
               $<$<BOOL:${ENABLE_HASH}>:hash.c>
               $<$<BOOL:${ENABLE_HMAC}>:hmac.c>
               $<$<BOOL:${ENABLE_SIGN_VERIFY}>:sign_verify.c>
               $<$<BOOL:${ENABLE_RNG}>:rng.c>
               $<$<BOOL:${ENABLE_CIPHER}>:cipher.c>
               $<$<BOOL:${ENABLE_TLS12}>:keymgr_derive_tls12.c>
               $<$<BOOL:${ENABLE_TLS12}>:sign_verify_tls12.c>)

target_include_directories(hsm PRIVATE ${INCLUDE_DIR}
                           ${SECO_INCLUDE_DIRS})

set(EXT_LIBS ${EXT_LIBS} ${SECO_LIBRARIES} ${ZLIB_LIBRARY} PARENT_SCOPE)
