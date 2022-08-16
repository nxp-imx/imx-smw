set(GROUP HSM)
set(CFG_FILE hsm_config.txt)
set(CMD ${TEST_CMD} ${CFG_FILE})
set(CMD_SUSPEND ${TEST_KEYMGR_SUSPEND_RESUME_CMD} ${CFG_FILE})

# Get all test definition files except those in multiple parts
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*_???.json)

if(ENABLE_TLS12)
	list(APPEND REM_TESTS_LIST U_HSM_TLS_001.json)
	list(APPEND REM_TESTS_LIST U_HSM_Generate_002.json)
else()
	list(APPEND REM_TESTS_LIST U_HSM_Derive_001.json)
	list(APPEND REM_TESTS_LIST F_HSM_TLS_001.json)
	list(APPEND REM_TESTS_LIST U_HSM_Generate_003.json)
	list(APPEND REM_TESTS_LIST U_HSM_Hmac_001.json)
endif()

foreach(REM_TESTS IN LISTS REM_TESTS_LIST)
    list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/${REM_TESTS})
endforeach()

set(CFG_FILES ${SMW_CONFIG_SRC_DIR}/${CFG_FILE})
add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD}")

# Create suspend resume test definition files list and install test
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/F_${GROUP}_Keymgr_001.?.json)

add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD_SUSPEND}")
