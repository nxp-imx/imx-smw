#
# Add ELE subsystem
#
if(CONFIG_SMW_ELE_RTOS)
        add_subsystem(ele)
        add_subdirectory(s3mu)
        add_subdirectory(ele_crypto)

        include(add_target_sources)

        add_private_sources(ele_rtos
                entry.c
                common.c
        )

        add_private_sources_ifdef(ele_rtos CONFIG_ENABLE_RNG rng.c)
        add_private_sources_ifdef(ele_rtos CONFIG_ENABLE_KEYMGR_MODULE key_group.c
                key_store.c
                key_policy.c
                lifecycle.c
                keymgr.c)

        add_private_directories(ele_rtos ${INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
endif()
