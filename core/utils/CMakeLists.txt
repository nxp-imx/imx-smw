set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:utils> PARENT_SCOPE)

add_library(utils OBJECT "")
set_target_properties(utils PROPERTIES C_VISIBILITY_PRESET hidden)
target_sources(utils PRIVATE
               list.c
               exec.c
               tlv.c
               base64.c
               name.c
               attr.c
               info.c
               hash.c
               mac.c)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND VERBOSE AND NOT VERBOSE EQUAL 0)
    target_sources(utils PRIVATE list_debug.c)
endif()

target_include_directories(utils PRIVATE ${INCLUDE_DIR})
