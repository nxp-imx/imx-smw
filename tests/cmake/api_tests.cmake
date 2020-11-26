set(API_CONFIG_FILE api_config.txt)
set(API_COMMAND ${TEST_CMD} ${API_CONFIG_FILE})

set(U_GENERATE_001_NAME U_API_Generate_001)
set(U_GENERATE_001_DEF ${SMW_TESTS_TARGET_DEF_DIR_FULL_PATH}/${U_GENERATE_001_NAME}.json)
set(U_GENERATE_001_CMD ${API_COMMAND} ${U_GENERATE_001_DEF})
add_test(NAME ${U_GENERATE_001_NAME} COMMAND ${U_GENERATE_001_CMD})
set_tests_properties(${U_GENERATE_001_NAME} PROPERTIES LABELS
		     "${UNITARY_LABEL};${API_LABEL};${GENERATE_LABEL}")

set(U_DELETE_001_NAME U_API_Delete_001)
set(U_DELETE_001_DEF ${SMW_TESTS_TARGET_DEF_DIR_FULL_PATH}/${U_DELETE_001_NAME}.json)
set(U_DELETE_001_CMD ${API_COMMAND} ${U_DELETE_001_DEF})
add_test(NAME ${U_DELETE_001_NAME} COMMAND ${U_DELETE_001_CMD})
set_tests_properties(${U_DELETE_001_NAME} PROPERTIES LABELS
		     "${UNITARY_LABEL};${API_LABEL};${DELETE_LABEL}")

set(U_HASH_001_NAME U_API_Hash_001)
set(U_HASH_001_DEF ${SMW_TESTS_TARGET_DEF_DIR_FULL_PATH}/${U_HASH_001_NAME}.json)
set(U_HASH_001_CMD ${API_COMMAND} ${U_HASH_001_DEF})
add_test(NAME ${U_HASH_001_NAME} COMMAND ${U_HASH_001_CMD})
set_tests_properties(${U_HASH_001_NAME} PROPERTIES LABELS
		     "${UNITARY_LABEL};${API_LABEL};${HASH_LABEL}")

install(FILES ${SMW_CONFIG_SRC_DIR}/${API_CONFIG_FILE}
        DESTINATION ${SMW_TESTS_TARGET_CONFIG_DIR})

FILE(GLOB U_API_TEST ${TEST_DEF_SRC_DIR}/U_API*.json)

foreach(file IN LISTS U_API_TEST)
	install(FILES ${file} DESTINATION ${SMW_TESTS_TARGET_DEF_DIR})
endforeach()