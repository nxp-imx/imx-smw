if(NOT DEFINED TEEC_ROOT OR NOT DEFINED TA_DEV_KIT_ROOT)
    message(STATUS "TEE not enabled")
    return()
endif()

find_package(Teec REQUIRED)
find_package(TA_dev_kit REQUIRED)

#
# Add TEE subsystem
#
add_subsystem(tee)

set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:tee> PARENT_SCOPE)

message(STATUS "    OPTEE client Library: ${TEEC_LIBRARY}")
message(STATUS "    OPTEE client Header : ${TEEC_INCLUDE_DIR}")
message(STATUS "    OPTEE TA Dev Kit    : ${TA_DEV_KIT_DIR}")

add_library(tee OBJECT "")
set_target_properties(tee PROPERTIES C_VISIBILITY_PRESET hidden)

#
# If at least one of the operation that supports MULTI_PART is enabled, context
# features are enabled
#
if (ENABLE_CIPHER)
    set(ENABLE_CONTEXT ON)
endif()

target_sources(tee PRIVATE
               tee.c
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c>
               $<$<BOOL:${ENABLE_HASH}>:hash.c>
               $<$<BOOL:${ENABLE_SIGN_VERIFY}>:sign_verify.c>
               $<$<BOOL:${ENABLE_HMAC}>:hmac.c>
               $<$<BOOL:${ENABLE_RNG}>:rng.c>
               $<$<BOOL:${ENABLE_CIPHER}>:cipher.c>
               $<$<BOOL:${ENABLE_CONTEXT}>:operation_context.c>)

target_include_directories(tee PRIVATE
                           ${TA_HOST_INCLUDE_DIR}
                           ${INCLUDE_DIR}
                           ./common)

target_include_directories(tee SYSTEM PRIVATE ${TEEC_INCLUDE_DIR})

set(EXT_LIBS ${EXT_LIBS} ${TEEC_LIBRARY} PARENT_SCOPE)

string(REGEX REPLACE "-gcc$" "-" CROSS_COMPILE  ${CMAKE_C_COMPILER})

add_subdirectory(lib_ta)
