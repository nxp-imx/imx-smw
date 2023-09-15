set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:devmgr> PARENT_SCOPE)


if(ENABLE_DEVMGR_MODULE)
   add_operation_implicit(DEVICE_GET_UUID)
endif()

if(ENABLE_DEVICE_ATTESTATION)
   add_operation(DEVICE_ATTESTATION)
endif()

if(ENABLE_DEVICE_LIFECYCLE)
   add_operation(DEVICE_LIFECYCLE)
endif()

add_library(devmgr OBJECT "")
target_sources(devmgr PRIVATE
               devmgr_weak.c
               lifecycle_weak.c
               $<$<BOOL:${ENABLE_DEVMGR_MODULE}>:devmgr.c>
               $<$<BOOL:${ENABLE_DEVICE_ATTESTATION}>:attestation.c>
               $<$<BOOL:${ENABLE_DEVICE_LIFECYCLE}>:lifecycle.c>)

target_include_directories(devmgr PRIVATE ${INCLUDE_DIR})

