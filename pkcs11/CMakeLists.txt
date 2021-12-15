cmake_minimum_required(VERSION 3.5)

project(smw_pkcs11 VERSION 1.0 LANGUAGES C)

#
# Define the Library compiler
#
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wall -Wextra -Werror)
endif()

add_library(${PROJECT_NAME} SHARED "")

include(gcov)

#
# Define the Library Capabilities
#
message(STATUS "List of PKCS11 options:")
option(PKCS11_MULTI_THREAD "PKCS11 Require Multiple Thread support")
message(STATUS "    Require Multiple Thread support: ${PKCS11_MULTI_THREAD}")
option(PKCS11_OS_THREAD_SUPPORT "PKCS11 Use OS Thread primitives")
message(STATUS "    Use OS Thread primitives: ${PKCS11_OS_THREAD_SUPPORT}")
option(PKCS11_OS_MUTEX_SUPPORT "PKCS11 Use OS Mutex primitives")
message(STATUS "    Use OS Mutex primitives: ${PKCS11_OS_MUTEX_SUPPORT}")

add_subdirectory(src)

# Define the library header interface, when the library is included
# in another target in the same build.
# Else header files are installed in system include path.
target_include_directories(${PROJECT_NAME}
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/import)

#
# Link with SMW Library
#
target_link_libraries(${PROJECT_NAME} PUBLIC smw)

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

set_target_properties(${PROJECT_NAME} PROPERTIES
    C_STANDARD 99
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON)

string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,--no-undefined")

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_LIBDIR} OPTIONAL)

# Install library headers interface
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/import/
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
	FILES_MATCHING PATTERN "*.h")

set(SMW_PKCS11_LIB "lib${PROJECT_NAME}.so.${PROJECT_VERSION_MAJOR}")
add_subdirectory(tests)
