set(OBJ_LIST ${OBJ_LIST} $<TARGET_OBJECTS:osal> PARENT_SCOPE)

#
# Force Position independent code to build object
# Fix some build toolchain like "arm-none-linux-gnueabihf"
#
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(SQLite3 REQUIRED)

add_library(osal OBJECT "")

set_target_properties(osal PROPERTIES C_VISIBILITY_PRESET hidden)

target_sources(osal PRIVATE
               osal.c
               obj_db.c
               config.c
               $<$<BOOL:${VERBOSE}>:osal_trace.c>
               $<$<CONFIG:DEBUG>:osal_debug.c>)

target_include_directories(osal
			   PRIVATE ${SQLite3_INCLUDE_DIR}
                           PRIVATE ${CMAKE_SOURCE_DIR}/inc
                           PUBLIC ${CMAKE_SOURCE_DIR}/public)

set(EXT_LIBS ${EXT_LIBS} SQLite3::SQLite3 PARENT_SCOPE)

install(FILES ${CMAKE_LOCAL_MODULE_PATH}/FindSQLite3.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake)

set(FIND_DEPENDENCIES ${FIND_DEPENDENCIES}
    "set(SQLite3_DIR \${PACKAGE_PREFIX_DIR})")
set(FIND_DEPENDENCIES ${FIND_DEPENDENCIES}
    "find_dependency(SQLite3 REQUIRED)" PARENT_SCOPE)

if(NOT YOCTO_BUILD)
  include(install_so_lib)
  install_so_lib(${SQLite3_LIBRARIES} ${CMAKE_INSTALL_LIBDIR})
endif()

macro(make_smw_conf)
  #
  # Setup the smw.conf to use the Secure Enclave subsystem as priority subsystem.
  #
  # Installation of the SMW configuration file(s) and Linux system configuration
  # file (smw.conf).
  #
  set(SMW_CONFIG_FILES_DIR      ${CMAKE_SOURCE_DIR}/osal/linux/config)
  set(SMW_CONFIG_FILES_INSTALL  ${CMAKE_INSTALL_PREFIX}/share/smw/config)
  set(SMW_SYS_CONF_FILE_INSTALL ${CMAKE_INSTALL_FULL_SYSCONFDIR}/opt/smw)
  set(SMW_SYS_CONF_SCRIPT       ${SMW_CONFIG_FILES_DIR}/smw_system_conf.sh)

  set(SRC_SMW_CONF ${SMW_CONFIG_FILES_DIR}/smw.conf)
  set(BIN_SMW_CONF ${CMAKE_BINARY_DIR}/osal/linux/config/smw.conf)

  unset(CONFIG_FILE)
  unset(MAKE_SMW_CONF)
  unset(MAKE_TEE_SE_CONF)
  unset(MAKE_ELE_SE_CONF)
  unset(MAKE_SECO_SE_CONF)

  # If TEE subsystem defined
  if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Teec AND
     DEFINED FIND_PACKAGE_MESSAGE_DETAILS_TA_dev_kit)
    set(CONFIG_FILE "${SMW_CONFIG_FILES_INSTALL}/tee_config.txt")

    install(FILES ${SMW_CONFIG_FILES_DIR}/tee_config.txt
            DESTINATION ${SMW_CONFIG_FILES_INSTALL})

    # This command must be added after the MASK_SMW_CONF in the
    # add_custom_target(make_smw_conf)
    set(MAKE_TEE_CONF ${SMW_SYS_CONF_SCRIPT}
                      in=${BIN_SMW_CONF}
                      conf=tee
                      ta_uuid=11b5c4aa-6d20-11ea-bc55-0242ac130003)
  endif()

  # If SECO subsystem defined
  if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Seco)
    set(CONFIG_FILE "${SMW_CONFIG_FILES_INSTALL}/seco_config.txt")

    if (ENABLE_TLS)
      install(FILES ${SMW_CONFIG_FILES_DIR}/seco_with_hmac_tls12_config.txt
              DESTINATION ${SMW_CONFIG_FILES_INSTALL}
              RENAME seco_config.txt)
    else()
      install(FILES ${SMW_CONFIG_FILES_DIR}/seco_config.txt
              DESTINATION ${SMW_CONFIG_FILES_INSTALL})
    endif()

    # This command must be added after the MASK_SMW_CONF in the
    # add_custom_target(make_smw_conf)
    set(MAKE_SECO_SE_CONF ${SMW_SYS_CONF_SCRIPT}
                      in=${BIN_SMW_CONF}
                      conf=seco
                      id=0x454C4500 nonce=0x534D57 replay=3000)
  endif()

  # If ELE subsystem defined
  if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Ele)
    set(CONFIG_FILE "${SMW_CONFIG_FILES_INSTALL}/ele_config.txt")

    install(FILES ${SMW_CONFIG_FILES_DIR}/ele_config.txt
            DESTINATION ${SMW_CONFIG_FILES_INSTALL})

    # This command must be added after the MASK_SMW_CONF in the
    # add_custom_target(make_smw_conf)
    set(MAKE_ELE_SE_CONF ${SMW_SYS_CONF_SCRIPT}
                      in=${BIN_SMW_CONF}
                      conf=ele
                      id=0x454C4500 nonce=0x534D57 shared=yes)
  endif()

  set(MAKE_SMW_CONF ${SMW_SYS_CONF_SCRIPT}
                    in=${SRC_SMW_CONF} out=${BIN_SMW_CONF}
                    conf=setup smw_config_file=${CONFIG_FILE})

  # If ELE subsystem defined add 8ULP specific configuration
  if(DEFINED FIND_PACKAGE_MESSAGE_DETAILS_Ele)
    #
    # i.MX8ULP specific configuration
    #
    install(FILES ${SMW_CONFIG_FILES_DIR}/ele_imx8ulp_config.txt
            DESTINATION ${SMW_CONFIG_FILES_INSTALL})

    set(MAKE_SMW_CONF_8ULP ${SMW_SYS_CONF_SCRIPT}
                      in=${BIN_SMW_CONF}
                      conf=setup-imx8ulp
                      smw_config_file="${SMW_CONFIG_FILES_INSTALL}/ele_imx8ulp_config.txt")

    #
    # i.MX95 specific configuration
    #
    install(FILES ${SMW_CONFIG_FILES_DIR}/ele_imx95_config.txt
            DESTINATION ${SMW_CONFIG_FILES_INSTALL})

    set(MAKE_SMW_CONF_95 ${SMW_SYS_CONF_SCRIPT}
                      in=${BIN_SMW_CONF}
                      conf=setup-imx95
                      smw_config_file="${SMW_CONFIG_FILES_INSTALL}/ele_imx95_config.txt")

    #
    # i.MX943 specific configuration
    #
    install(FILES ${SMW_CONFIG_FILES_DIR}/ele_imx943_config.txt
    DESTINATION ${SMW_CONFIG_FILES_INSTALL})

    set(MAKE_SMW_CONF_943 ${SMW_SYS_CONF_SCRIPT}
              in=${BIN_SMW_CONF}
              conf=setup-imx943
              smw_config_file="${SMW_CONFIG_FILES_INSTALL}/ele_imx943_config.txt")

    # Order in the command must be respected to append the resulting smw.conf
    # file generated with the first command.
    add_custom_target(make_smw_conf
                      ALL
                      COMMAND ${MAKE_SMW_CONF}
                      COMMAND ${MAKE_SMW_CONF_8ULP}
                      COMMAND ${MAKE_SMW_CONF_95}
                      COMMAND ${MAKE_SMW_CONF_943}
                      COMMAND ${MAKE_ELE_SE_CONF}
                      COMMAND ${MAKE_TEE_CONF}
                      COMMENT "Generate Linux system configuration ${BIN_SMW_CONF}")
  else()
    add_custom_target(make_smw_conf
                      ALL
                      COMMAND ${MAKE_SMW_CONF}
                      COMMAND ${MAKE_SECO_SE_CONF}
                      COMMAND ${MAKE_TEE_CONF}
                      COMMENT "Generate Linux system configuration ${BIN_SMW_CONF}")
  endif()

  install(FILES ${BIN_SMW_CONF}
          DESTINATION ${SMW_SYS_CONF_FILE_INSTALL})

  install(PROGRAMS ${SMW_SYS_CONF_SCRIPT}
          DESTINATION ${SMW_SYS_CONF_FILE_INSTALL})
endmacro()
