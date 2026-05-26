file(GLOB pkcs11_src *.c)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
   list(FILTER pkcs11_src EXCLUDE REGEX "trace.c$")
endif()

target_sources(${PROJECT_NAME} PRIVATE ${pkcs11_src})

configure_file(./include/pkcs11smw_config.h.in ./include/pkcs11smw_config.h)

target_include_directories(${PROJECT_NAME} PRIVATE
	./include
	${CMAKE_CURRENT_BINARY_DIR}/include
	${CMAKE_SOURCE_DIR}/inc)

add_subdirectory(utils)
add_subdirectory(ifsmw)
add_subdirectory(objects)
