set(GROUP ELE)
set(CMD ${TEST_CMD})

# Get all test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

# Remove failing test due to ELE Library or FW issues
list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/F_${GROUP}_Thread_001.json)

add_and_install_tests("${TESTS}" "${CMD}")

# Install the cst template files
install(DIRECTORY ${SMW_CST_TEMPLATE_DIR}
	DESTINATION ${SMW_TESTS_TARGET_CST_TEMPLAGE_DIR}
	EXCLUDE_FROM_ALL
	COMPONENT ${PROJECT_NAME})
