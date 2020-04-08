set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:osal> PARENT_SCOPE)
add_library(osal OBJECT ${OS}/osal.c ${INCLUDE_DIR})
target_include_directories(osal PRIVATE ${INCLUDE_DIR})
