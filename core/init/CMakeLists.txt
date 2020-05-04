set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:init> PARENT_SCOPE)

add_library(init OBJECT init.c ${INCLUDE_DIR})
set_target_properties(init PROPERTIES C_VISIBILITY_PRESET hidden)
target_include_directories(init PRIVATE ${INCLUDE_DIR})
