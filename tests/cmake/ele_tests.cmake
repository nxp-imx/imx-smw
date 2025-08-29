set(GROUP ELE)
set(CMD ${TEST_CMD})

# Get all test definition files
file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}_*.json)

# These tests depend on TLS feature support
if(NOT ENABLE_TLS)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_005.json)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_006.json)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_007.json)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_008.json)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_009.json)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_010.json)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_011.json)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_013.json)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_014.json)
	list(APPEND REM_TESTS_LIST U_${GROUP}_Derive_015.json)
endif()

# Remove failing test due to ELE Library or FW issues
list(APPEND REM_TESTS_LIST ${TEST_DEF_SRC_DIR}/F_${GROUP}_Thread_001.json)

foreach(REM_TESTS IN LISTS REM_TESTS_LIST)
	list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/${REM_TESTS})
endforeach()

add_and_install_tests("${TESTS}" "${CMD}")

# Install the cst template files
install(DIRECTORY ${SMW_CST_TEMPLATE_DIR}
	DESTINATION ${SMW_TESTS_TARGET_CST_TEMPLAGE_DIR}
	EXCLUDE_FROM_ALL
	COMPONENT ${PROJECT_NAME})
