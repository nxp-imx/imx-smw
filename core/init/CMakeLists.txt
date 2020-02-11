set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:init> PARENT_SCOPE)

add_library(init OBJECT init.c ${INCLUDE_DIR})
target_include_directories(init PUBLIC ${INCLUDE_DIR})
