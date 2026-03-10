project(tss2-tcti-smw VERSION 0.1 LANGUAGES C)

if(NOT DEFINED TSS2_ROOT)
    message(STATUS "TPM2 not enabled")
    return()
endif()

find_package(Tss2 REQUIRED)

message(STATUS "    TSS2 Libraries: ${TSS2_LIBRARIES}")
message(STATUS "    TSS2 Headers  : ${TSS2_INCLUDE_DIRS}")

add_library(${PROJECT_NAME} SHARED "")

add_subdirectory(src)

#
# Link with SMW Library and TSS2 shared libraries
#
target_link_libraries(${PROJECT_NAME} PRIVATE smw)
target_link_libraries(${PROJECT_NAME} PUBLIC Tss2::Mu Tss2::Rc)

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_STANDARD 99
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,--no-undefined")

# Define the library header interface, when the library is included
# in another target in the same build.
# Else header files are installed in system include path.
target_include_directories(${PROJECT_NAME}
	PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/public>
	       $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}>)

install(TARGETS ${PROJECT_NAME} EXPORT SMWTargets
  DESTINATION ${CMAKE_INSTALL_LIBDIR} OPTIONAL)

# Install library headers interface
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/public/
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
	FILES_MATCHING PATTERN "*.h")

install(FILES ${CMAKE_LOCAL_MODULE_PATH}/FindTss2.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake)

if(NOT YOCTO_BUILD)
  include(install_so_lib)
  install(IMPORTED_RUNTIME_ARTIFACTS Tss2::Mu Tss2::Rc)
  install_so_lib("${TSS2_LIBRARIES}" ${CMAKE_INSTALL_LIBDIR})
endif()
