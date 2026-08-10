# ELA requires ELE to be enabled first
if(NOT DEFINED ELE_ROOT)
    message(STATUS "ELA requires ELE subsystem - ELE_ROOT not defined")
    return()
endif()

if(NOT Ele_FOUND)
    message(STATUS "ELA requires ELE subsystem - ELE not found")
    return()
endif()

# Find ELA package using ELE_ROOT path
# ELA library (libprime.so) and header (prime.h) should be in ELE_ROOT
find_package(Ela REQUIRED)

message(STATUS "  ELA Library: ${ELA_LIBRARY}")
message(STATUS "  ELA Headers: ${ELA_INCLUDE_DIRS}")

set(ela_srcs
    ela_dispatcher.c
    common.c
    $<$<BOOL:${ENABLE_CIPHER}>:${CMAKE_CURRENT_SOURCE_DIR}/cipher.c>
    $<$<BOOL:${ENABLE_AEAD}>:${CMAKE_CURRENT_SOURCE_DIR}/aead.c>
    $<$<BOOL:${ENABLE_MAC}>:${CMAKE_CURRENT_SOURCE_DIR}/mac.c>)

# Add ELA sources to the parent 'ele' target
target_sources(ele PRIVATE ${ela_srcs})

# Add ELA include directories to 'ele' target
target_include_directories(ele PRIVATE
                           ${INCLUDE_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR}
                           ${ELA_INCLUDE_DIRS})

# Link ELA library to 'ele' target
target_link_libraries(ele PRIVATE Ela::Ela)

# Propagate ELA library to parent scope
set(EXT_LIBS ${EXT_LIBS} Ela::Ela PARENT_SCOPE)

install(FILES ${CMAKE_LOCAL_MODULE_PATH}/FindEla.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake)

set(FIND_DEPENDENCIES ${FIND_DEPENDENCIES}
    "set(ELE_ROOT \${PACKAGE_PREFIX_DIR})")
set(FIND_DEPENDENCIES ${FIND_DEPENDENCIES}
    "find_dependency(Ela REQUIRED)" PARENT_SCOPE)

if(NOT YOCTO_BUILD)
  include(install_so_lib)
  install_so_lib(${ELA_LIBRARIES} ${CMAKE_INSTALL_LIBDIR})
endif()