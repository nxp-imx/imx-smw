file(GLOB tss2_src *.c)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
	find_file(TRACE_C trace.c ${CMAKE_CURRENT_SOURCE_DIR})
	list(REMOVE_ITEM tss2_src ${TRACE_C})
	unset(TRACE_C CACHE)
endif()

target_sources(${PROJECT_NAME} PRIVATE ${tss2_src})

target_include_directories(${PROJECT_NAME} PRIVATE
	./include
        ${TSS2_INCLUDE_DIRS}
	${CMAKE_SOURCE_DIR}/inc)

add_subdirectory(utils)
add_subdirectory(commands)
