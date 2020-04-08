if(ENABLE_HSM)
    add_subsystem(hsm)
endif()

set(SMW_LIBS ${SMW_LIBS} PARENT_SCOPE)
