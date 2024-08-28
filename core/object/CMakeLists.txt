set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:object> PARENT_SCOPE)

add_library(object OBJECT "")
target_sources(object PRIVATE
               object_weak.c
               $<$<BOOL:${ENABLE_OBJECT_MODULE}>:object.c>)
target_include_directories(object PRIVATE ${INCLUDE_DIR})
