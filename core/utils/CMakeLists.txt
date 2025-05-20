set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:utils> PARENT_SCOPE)

add_library(utils OBJECT "")
set_target_properties(utils PROPERTIES C_VISIBILITY_PRESET hidden)
target_sources(utils PRIVATE
               aead.c
               attrs.c
               base64.c
               cipher.c
               exec.c
               hash.c
               info.c
               list.c
               key.c
               mac.c
               name.c
               object_db.c
               object_query.c
               operation_context.c)

if(ENABLE_STORAGE_MODULE OR ENABLE_KEYMGR_MODULE)
   add_operation_implicit(IS_OBJECT_PRESENT)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND VERBOSE AND NOT VERBOSE EQUAL 0)
    target_sources(utils PRIVATE list_debug.c)
endif()

target_include_directories(utils PRIVATE ${INCLUDE_DIR})
