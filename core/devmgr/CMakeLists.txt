if(ENABLE_DEVMGR_MODULE)
   add_operation_implicit(DEVICE_GET_UUID)
endif()

if(ENABLE_DEVICE_ATTESTATION)
   add_operation(DEVICE_ATTESTATION)
endif()

if(ENABLE_DEVICE_LIFECYCLE)
   add_operation(DEVICE_LIFECYCLE)
endif()

if(ENABLE_DEVICE_REPROVISION)
   add_operation(DEVICE_REPROVISION)
endif()

if(NOT BUILD_ZEPHYR)
   set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:devmgr> PARENT_SCOPE)

   add_library(devmgr OBJECT "")
endif()

include(add_target_sources)

add_private_sources(devmgr devmgr_weak.c)

add_private_sources_ifdef(devmgr ENABLE_DEVMGR_MODULE devmgr.c)
add_private_sources_ifdef(devmgr ENABLE_DEVICE_ATTESTATION attestation.c)
add_private_sources_ifdef(devmgr ENABLE_DEVICE_LIFECYCLE lifecycle.c)
add_private_sources_ifdef(devmgr ENABLE_DEVICE_REPROVISION reprovision.c)

add_private_directories(devmgr ${INCLUDE_DIR})
