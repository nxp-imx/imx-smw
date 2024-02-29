set(GROUP SECO)
set(CFG_FILE seco_config.txt)
set(CMD ${TEST_CMD} ${CFG_FILE})

# Get all test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

if(ENABLE_TLS12)
	list(APPEND REM_TESTS_LIST U_SECO_TLS_001.json)
	list(APPEND REM_TESTS_LIST U_SECO_Generate_002.json)
else()
	list(APPEND REM_TESTS_LIST U_SECO_Derive_001.json)
	list(APPEND REM_TESTS_LIST U_SECO_Derive_002.json)
	list(APPEND REM_TESTS_LIST F_SECO_TLS_001.json)
	list(APPEND REM_TESTS_LIST U_SECO_Generate_003.json)
	list(APPEND REM_TESTS_LIST U_SECO_Mac_002.json)
endif()

foreach(REM_TESTS IN LISTS REM_TESTS_LIST)
	list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/${REM_TESTS})
endforeach()

set(CFG_FILES ${SMW_CONFIG_SRC_DIR}/${CFG_FILE})
add_and_install_tests("${TESTS}" "${CFG_FILES}" "${CMD}")
