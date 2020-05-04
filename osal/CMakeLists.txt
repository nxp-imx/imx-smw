set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:osal> PARENT_SCOPE)
add_library(osal OBJECT ${OS}/osal.c ${INCLUDE_DIR})
set_target_properties(osal PROPERTIES C_VISIBILITY_PRESET hidden)
target_include_directories(osal PRIVATE ${INCLUDE_DIR})
