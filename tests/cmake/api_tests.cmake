set(GROUP API)
set(CMD ${TEST_CMD})

# Install config files
file(GLOB CFG_FILES ${SMW_CONFIG_SRC_DIR}/config_*.txt)

file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}*.json)

add_and_install_tests("${TESTS}" "${CMD}")

# Install the test configuration files
install(FILES ${CFG_FILES}
	DESTINATION ${SMW_TESTS_TARGET_CONFIG_DIR}
	EXCLUDE_FROM_ALL
	COMPONENT ${PROJECT_NAME})
