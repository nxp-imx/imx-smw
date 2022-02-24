set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:keymgr> PARENT_SCOPE)

if(ENABLE_KEYMGR_MODULE)
    add_operation(GENERATE_KEY)
    add_operation(DERIVE_KEY)
    add_operation(UPDATE_KEY)
    add_operation(IMPORT_KEY)
    add_operation(EXPORT_KEY)
    add_operation(DELETE_KEY)
endif()

add_library(keymgr OBJECT "")
target_sources(keymgr PRIVATE
               keymgr_weak.c
               $<$<BOOL:${ENABLE_KEYMGR_MODULE}>:keymgr.c keymgr_derive.c keymgr_db.c>)
target_include_directories(keymgr PRIVATE ${INCLUDE_DIR})
