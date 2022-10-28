file(GLOB ifsmw_src *.c)

option(SMW_DEVICE_ONLY "SMW Device only" ON)
message(STATUS "    Abstract SMW's Secure Subsystems: ${SMW_DEVICE_ONLY}")

set(NB_IFSWM_DEV 1)
list(APPEND list_ifsmw "smw")

if (NOT SMW_DEVICE_ONLY)
foreach(src IN LISTS ifsmw_src)
  get_filename_component(filename ${src} NAME)
  if(NOT ${filename} MATCHES "smw_dev.c" AND ${filename} MATCHES "_dev.c$")
     string(REGEX REPLACE "_dev.c$" "" ifsmw_name ${filename})
     list(APPEND list_ifsmw ${ifsmw_name})
     MATH(EXPR NB_IFSWM_DEV "${NB_IFSWM_DEV} + 1")
  endif()
endforeach()
endif()
message(STATUS "    SMW devices: ${list_ifsmw}")
message(STATUS "    Nb SMW devices: ${NB_IFSWM_DEV}")

#
# For each defined devices (SMW's Secure Subsystem name)
# Build:
#    - list of device information
#    - list of cryptoki mechanism information function
string(APPEND DEV_INFO "\n")
string(APPEND DEV_MECH_INFO "\n")
foreach(dev IN LISTS list_ifsmw)
  string(APPEND DECLARE_DEV_INFO "extern const struct libdev ${dev}_info;\n")
  string(APPEND DECLARE_DEV_MECH_INFO "FUNC_DEV_MECH_INFO(${dev}_mech_info);\n")
  string(APPEND DEV_INFO "{ .dev = &${dev}_info }, \n")
  string(APPEND DEV_MECH_INFO "${dev}_mech_info, \n")
endforeach()

configure_file(dev_config.c.in dev_config.c)
configure_file(dev_config.h.in dev_config.h)

list(APPEND ifsmw_src ${CMAKE_CURRENT_BINARY_DIR}/dev_config.c)

target_sources(${PROJECT_NAME} PRIVATE ${ifsmw_src})

target_include_directories(${PROJECT_NAME} PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR})

