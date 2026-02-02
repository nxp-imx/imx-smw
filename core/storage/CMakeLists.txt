if(ENABLE_STORAGE_MODULE)
   add_operation(STORAGE_STORE)
   add_operation(STORAGE_RETRIEVE)
   add_operation(STORAGE_DELETE)
   add_operation_implicit(STORAGE_GET_DATA_INFO)
endif()

if(NOT BUILD_ZEPHYR)
   set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:storage> PARENT_SCOPE)

   add_library(storage OBJECT "")
endif()

include(add_target_sources)

add_private_sources(storage storage_weak.c)
add_private_sources_ifdef(storage ENABLE_STORAGE_MODULE storage.c)
add_private_directories(storage ${INCLUDE_DIR})
