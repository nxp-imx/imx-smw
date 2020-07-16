if(ENABLE_HSM)
    add_subsystem(hsm)
endif()

if(ENABLE_TEE)
    add_subsystem(tee)
endif()

set(OBJ_LIST ${OBJ_LIST} PARENT_SCOPE)
set(EXT_LIBS ${EXT_LIBS} PARENT_SCOPE)
