set(GROUP API)
set(CMD ${TEST_CMD})

# Install config files
file(GLOB CFG_FILES ${SMW_CONFIG_SRC_DIR}/config_*.txt)

file(GLOB TESTS ${TEST_DEF_SRC_DIR}/*_${GROUP}*.json)

# These tests depend on TLS feature support
if(NOT ENABLE_TLS)
  list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Derive_004.json)
  list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Derive_005.json)
endif()

if(NOT TEE_TESTS_ENABLED)
  # Remove all configuration test due to missing TEE subsystem
  list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Config_001.json)
  list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Config_002.json)
  list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Config_003.json)
  list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Config_004.json)

  if(SECO_TESTS_ENABLED)
      list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Derive_001.json)
      list(REMOVE_ITEM TESTS ${TEST_DEF_SRC_DIR}/U_${GROUP}_Export_002.json)
  endif()
endif()

add_and_install_tests("${TESTS}" "${CMD}")

# Install the test configuration files
install(FILES ${CFG_FILES}
	DESTINATION ${SMW_TESTS_TARGET_CONFIG_DIR}
	EXCLUDE_FROM_ALL
	COMPONENT ${PROJECT_NAME})
