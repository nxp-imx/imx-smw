if(NOT DEFINED TEEC_ROOT OR NOT DEFINED TA_DEV_KIT_ROOT)
    message(STATUS "TEE not enabled")
    return()
endif()

find_package(TEEC REQUIRED)
find_package(TAdevkit REQUIRED)

#
# Add TEE subsystem
#
add_subsystem(tee)

set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:tee> PARENT_SCOPE)

message(STATUS "    OPTEE client Library: ${TEEC_LIBRARY}")
message(STATUS "    OPTEE client Header : ${TEEC_INCLUDE_DIR}")
message(STATUS "    OPTEE TA Dev Kit    : ${TA_DEV_KIT_DIR}")

set(TA_BINARY 11b5c4aa-6d20-11ea-bc55-0242ac130003)
set(TA_FILE ${TA_BINARY}.ta)

add_library(tee OBJECT "")
set_target_properties(tee PROPERTIES C_VISIBILITY_PRESET hidden)

target_sources(tee PRIVATE
               tee.c
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c>
               $<$<BOOL:${ENABLE_HASH}>:hash.c>
               $<$<BOOL:${ENABLE_SIGN_VERIFY}>:sign_verify.c>
               $<$<BOOL:${ENABLE_HMAC}>:hmac.c>)

target_include_directories(tee PRIVATE ${INCLUDE_DIR}
                           ${TEEC_INCLUDE_DIR}
                           ./common)

set(EXT_LIBS ${EXT_LIBS} ${TEEC_LIBRARY} PARENT_SCOPE)

# Invoke TA Makefile
set(TA_MAKEFILE_PATH ${CMAKE_SOURCE_DIR}/core/subsystems/tee/ta)

set(TA_BUILD_DIR ${CMAKE_BINARY_DIR}/ta)
string(REGEX REPLACE "-gcc$" "-" CROSS_COMPILE  ${CMAKE_C_COMPILER})

set(TA_CMD make -C ${TA_MAKEFILE_PATH}
                BINARY=${TA_BINARY}
                TA_EXPORT_DIR=${TA_DEV_KIT_DIR}
                TA_CROSS_COMPILE=${CROSS_COMPILE}
                TA_LOG_LEVEL=${VERBOSE}
                O=${TA_BUILD_DIR}
                )

include(ExternalProject)
ExternalProject_Add(smw_tee_ta
	CONFIGURE_COMMAND ""
	INSTALL_COMMAND ""
	BUILD_ALWAYS True
	SOURCE_DIR ${CMAKE_SOURCE_DIR}/core/subsystems/tee/ta
	BINARY_DIR ${CMAKE_BINARY_DIR}/ta
	TMP_DIR ${CMAKE_BINARY_DIR}/ta
	BUILD_COMMAND ${TA_CMD})

install(FILES ${TA_BUILD_DIR}/${TA_FILE} DESTINATION ${DESTDIR}/lib/optee_armtz)
