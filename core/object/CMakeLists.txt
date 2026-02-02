if(NOT BUILD_ZEPHYR)
        set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:object> PARENT_SCOPE)

        add_library(object OBJECT "")
endif()

include(add_target_sources)

add_private_sources(object object_weak.c)
add_private_sources_ifdef(object ENABLE_OBJECT_MODULE object.c)
add_private_directories(object ${INCLUDE_DIR})
