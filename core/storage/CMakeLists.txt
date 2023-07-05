set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:storage> PARENT_SCOPE)


if(ENABLE_STORAGE_MODULE)
   add_operation(STORAGE_STORE)
   add_operation(STORAGE_RETRIEVE)
   add_operation(STORAGE_DELETE)
endif()

add_library(storage OBJECT "")
target_sources(storage PRIVATE
               storage_weak.c
               $<$<BOOL:${ENABLE_STORAGE_MODULE}>:storage.c>)

target_include_directories(storage PRIVATE ${INCLUDE_DIR})

