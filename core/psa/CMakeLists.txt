set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:psa> PARENT_SCOPE)

add_library(psa OBJECT "")
set_target_properties(psa PROPERTIES C_VISIBILITY_PRESET hidden)
target_sources(psa PRIVATE
               asn1.c
               common.c
               crypto.c
               initial_attestation.c
               internal_trusted_storage.c
               protected_storage.c
               keymgr.c
               util_status.c)
target_include_directories(psa PRIVATE ${INCLUDE_DIR})
