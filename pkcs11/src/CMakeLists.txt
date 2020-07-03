file(GLOB pkcs11_src *.c)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
	find_file(TRACE_C trace.c ${CMAKE_CURRENT_SOURCE_DIR})
	list(REMOVE_ITEM pkcs11_src ${TRACE_C})
	unset(TRACE_C CACHE)
endif()

target_sources(${PROJECT_NAME} PRIVATE ${pkcs11_src})

configure_file(./include/pkcs11smw_config.h.in ./include/pkcs11smw_config.h)

target_include_directories(${PROJECT_NAME} PRIVATE
	./include
	${CMAKE_CURRENT_BINARY_DIR}/include)

add_subdirectory(ifsmw)
add_subdirectory(objects)
