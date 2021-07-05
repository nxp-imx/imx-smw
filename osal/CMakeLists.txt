set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:osal> PARENT_SCOPE)

#
# Force Position independent code to build object
# Fix some build toolchain like "arm-none-linux-gnueabihf"
#
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(osal OBJECT ${OS}/osal.c)
set_target_properties(osal PROPERTIES C_VISIBILITY_PRESET hidden)
target_include_directories(osal
                           PRIVATE ${CMAKE_SOURCE_DIR}/inc
                           PUBLIC ${CMAKE_SOURCE_DIR}/public)
