set(TEE_CONFIG_FILE tee_config.txt)
set(TEE_COMMAND ${TEST_CMD} ${TEE_CONFIG_FILE})
set(TEE_TEST_KEYMGR_SUSPEND_RESUME_COMMAND ${TEST_KEYMGR_SUSPEND_RESUME_CMD} ${TEE_CONFIG_FILE})

# Install config file
install(FILES ${SMW_CONFIG_SRC_DIR}/${TEE_CONFIG_FILE}
	DESTINATION ${SMW_TESTS_TARGET_CONFIG_DIR}
	EXCLUDE_FROM_ALL
	COMPONENT ${PROJECT_NAME})

# Get all TEE test definition files except those in multiple parts
FILE(GLOB TEE_TESTS ${TEST_DEF_SRC_DIR}/*_TEE*_???.json)

add_and_install_tests("${TEE_TESTS}" "${TEE_COMMAND}")

# Create suspend resume test definition files list and install test
set(F_KEYMGR_004_1 F_TEE_Keymgr_004.1.json)
set(F_KEYMGR_004_2 F_TEE_Keymgr_004.2.json)

list(APPEND TEE_SUSPEND_RESUME_TESTS ${TEST_DEF_SRC_DIR}/${F_KEYMGR_004_1})
list(APPEND TEE_SUSPEND_RESUME_TESTS ${TEST_DEF_SRC_DIR}/${F_KEYMGR_004_2})

add_and_install_tests("${TEE_SUSPEND_RESUME_TESTS}"
		      "${TEE_TEST_KEYMGR_SUSPEND_RESUME_COMMAND}")
