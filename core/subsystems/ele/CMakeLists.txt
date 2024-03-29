if(NOT DEFINED ELE_ROOT)
    message(STATUS "ELE (EdgeLock Enclave) not enabled")
    return()
endif()

find_package(Ele REQUIRED)

#
# Add ELE subsystem
#
add_subsystem(ele)

set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:ele> PARENT_SCOPE)

message(STATUS "    ELE  Libraries: ${ELE_LIBRARIES}")
message(STATUS "    ELE  Headers  : ${ELE_INCLUDE_DIRS}")

add_library(ele OBJECT "")
set_target_properties(ele PROPERTIES C_VISIBILITY_PRESET hidden)

target_sources(ele PRIVATE
               entry.c
               common.c
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c keymgr_derive.c
                    key_policy.c lifecycle.c>
               $<$<BOOL:${ENABLE_HASH}>:hash.c>
               $<$<BOOL:${ENABLE_MAC}>:mac.c>
               $<$<BOOL:${ENABLE_SIGN_VERIFY}>:sign_verify.c>
               $<$<BOOL:${ENABLE_RNG}>:rng.c>
               $<$<BOOL:${ENABLE_CIPHER}>:cipher.c>
               $<$<BOOL:${ENABLE_DEVMGR_MODULE}>:devmgr.c>
               $<$<BOOL:${ENABLE_DEVICE_ATTESTATION}>:devmgr_attest.c>
               $<$<BOOL:${ENABLE_DEVICE_LIFECYCLE}>:devmgr_lifecycle.c>
               $<$<BOOL:${ENABLE_STORAGE_MODULE}>:storage.c>)

target_include_directories(ele PRIVATE
                           ${INCLUDE_DIR}
                           ${ELE_INCLUDE_DIRS})

set(EXT_LIBS ${EXT_LIBS} ${ELE_LIBRARIES} PARENT_SCOPE)
