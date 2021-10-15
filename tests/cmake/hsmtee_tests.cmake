set(HSMTEE_CONFIG_FILE api_config.txt)
set(HSMTEE_COMMAND ${TEST_CMD} ${HSMTEE_CONFIG_FILE})

# Install config file
install(FILES ${SMW_CONFIG_SRC_DIR}/${HSMTEE_CONFIG_FILE}
	DESTINATION ${SMW_TESTS_TARGET_CONFIG_DIR}
	EXCLUDE_FROM_ALL
	COMPONENT ${PROJECT_NAME})

# Get all HSMTEE test definition files except those in multiple parts
FILE(GLOB HSMTEE_TESTS ${TEST_DEF_SRC_DIR}/*_HSMTEE_*_???.json)

add_and_install_tests("${HSMTEE_TESTS}" "${HSMTEE_COMMAND}")
