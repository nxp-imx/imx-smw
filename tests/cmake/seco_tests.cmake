set(GROUP SECO)
set(CMD ${TEST_CMD})

# Get all test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

if(ENABLE_TLS)
	list(APPEND REM_TESTS_LIST U_SECO_TLS_001.json)
	list(APPEND REM_TESTS_LIST U_SECO_Generate_002.json)
else()
	list(APPEND REM_TESTS_LIST U_SECO_Derive_001.json)
	list(APPEND REM_TESTS_LIST U_SECO_Derive_002.json)
	list(APPEND REM_TESTS_LIST U_SECO_Derive_003.json)
	list(APPEND REM_TESTS_LIST F_SECO_TLS_001.json)
	list(APPEND REM_TESTS_LIST U_SECO_Generate_003.json)
	list(APPEND REM_TESTS_LIST U_SECO_Mac_002.json)
endif()

foreach(REM_TESTS IN LISTS REM_TESTS_LIST)
	list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/${REM_TESTS})
endforeach()

add_and_install_tests("${TESTS}" "${CMD}")

# Install config files
file(GLOB CFG_FILES ${SMW_CONFIG_SRC_DIR}/config_seco*.txt)

# Install the test configuration files
install(FILES ${CFG_FILES}
	DESTINATION ${SMW_TESTS_TARGET_CONFIG_DIR}
	EXCLUDE_FROM_ALL
	COMPONENT ${PROJECT_NAME})
