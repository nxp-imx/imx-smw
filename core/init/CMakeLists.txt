if(NOT BUILD_ZEPHYR)
        set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:init> PARENT_SCOPE)

        add_library(init OBJECT "")
        set_target_properties(init PROPERTIES C_VISIBILITY_PRESET hidden)
endif()

include(add_target_sources)

add_private_sources(init init.c)
add_private_directories(init ${INCLUDE_DIR})
