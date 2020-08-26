include(add_component)

set(CORE_SRC_INC ${CMAKE_CURRENT_SOURCE_DIR}/inc)
set(CORE_BIN_INC ${CMAKE_CURRENT_BINARY_DIR}/inc)
set(INCLUDE_DIR ${INCLUDE_DIR} ${CORE_SRC_INC} ${CORE_BIN_INC})

#
#Initialize Cache variables use to build source files
#
define_property(GLOBAL PROPERTY PROP_SUBSYSTEM_ID
    BRIEF_DOCS "Subsytem" FULL_DOCS "Subsystem IDs")
define_property(GLOBAL PROPERTY PROP_SUBSYSTEM_EXPORT
    BRIEF_DOCS "Subsytem" FULL_DOCS "Subsystem exports")
define_property(GLOBAL PROPERTY PROP_SUBSYSTEM_NAME
    BRIEF_DOCS "Subsystem" FULL_DOCS "Subsystem names")
define_property(GLOBAL PROPERTY PROP_SUBSYSTEM_FUNC
    BRIEF_DOCS "Subsystem" FULL_DOCS "Subsytem functions")
define_property(GLOBAL PROPERTY PROP_OPERATION_ID
    BRIEF_DOCS "Operation" FULL_DOCS "Operation IDs")
define_property(GLOBAL PROPERTY PROP_OPERATION_EXPORT
    BRIEF_DOCS "Operation" FULL_DOCS "Operation exports")
define_property(GLOBAL PROPERTY PROP_OPERATION_NAME
    BRIEF_DOCS "Operation" FULL_DOCS "Operation names")
define_property(GLOBAL PROPERTY PROP_OPERATION_FUNC
    BRIEF_DOCS "Operation" FULL_DOCS "Operation functions")

set(NB_SUBSYSTEM 0)
set(SUBSYSTEM_ID "SUBSYSTEM_ID")
set(ENUM_SUBSYSTEM_ID "enum subsystem_id")
set(STRUCT_SUBSYSTEM_FUNC "struct subsystem_func")
set(RETURN_SUBSYSTEM_FUNC "${STRUCT_SUBSYSTEM_FUNC} \*")

set(NB_OPERATION 0)
set(OPERATION_ID "OPERATION_ID")
set(ENUM_OPERATION_ID "enum operation_id")
set(STRUCT_OPERATION_FUNC "struct operation_func")
set(RETURN_OPERATION_FUNC "${STRUCT_OPERATION_FUNC} \*")

macro(add_subsystem subsystem)
    MATH(EXPR NB_SUBSYSTEM "${NB_SUBSYSTEM} + 1")
    SET(NB_SUBSYSTEM ${NB_SUBSYSTEM} PARENT_SCOPE)
    add_component(${subsystem} ${SUBSYSTEM_ID} RETURN_SUBSYSTEM_FUNC
                  PROP_SUBSYSTEM_ID
                  PROP_SUBSYSTEM_EXPORT
                  PROP_SUBSYSTEM_NAME
                  PROP_SUBSYSTEM_FUNC)
endmacro()

macro(add_operation operation)
    MATH(EXPR NB_OPERATION "${NB_OPERATION} + 1")
    SET(NB_OPERATION ${NB_OPERATION} PARENT_SCOPE)
    add_component(${operation} ${OPERATION_ID} RETURN_OPERATION_FUNC
                  PROP_OPERATION_ID
                  PROP_OPERATION_EXPORT
                  PROP_OPERATION_NAME
                  PROP_OPERATION_FUNC)
endmacro()

add_subdirectory(utils)
add_subdirectory(init)
add_subdirectory(subsystems/hsm)
add_subdirectory(subsystems/tee)
add_subdirectory(keymgr)
add_subdirectory(crypto)

get_property(LIST_SUBSYSTEM_ID GLOBAL PROPERTY PROP_SUBSYSTEM_ID)
get_property(LIST_SUBSYSTEM_EXPORT GLOBAL PROPERTY PROP_SUBSYSTEM_EXPORT)
get_property(LIST_SUBSYSTEM_NAME GLOBAL PROPERTY PROP_SUBSYSTEM_NAME)
get_property(LIST_SUBSYSTEM_FUNC GLOBAL PROPERTY PROP_SUBSYSTEM_FUNC)
get_property(LIST_OPERATION_ID GLOBAL PROPERTY PROP_OPERATION_ID)
get_property(LIST_OPERATION_EXPORT GLOBAL PROPERTY PROP_OPERATION_EXPORT)
get_property(LIST_OPERATION_NAME GLOBAL PROPERTY PROP_OPERATION_NAME)
get_property(LIST_OPERATION_FUNC GLOBAL PROPERTY PROP_OPERATION_FUNC)

if(${NB_SUBSYSTEM} EQUAL 0)
    message(FATAL_ERROR "No subsystem defined, at least one must be defined")
endif()
if(${NB_OPERATION} EQUAL 0)
    message(FATAL_ERROR "No operation defined, at least one must be defined")
endif()

#[[The subdirectory config must be the last one to be added because
config/CMakeLists.txt calls configure_file() that requires cache variables
that are set by several CMakeLists.txt from the subdirectories above.]]
add_subdirectory(config)

configure_file(${CORE_SRC_INC}/operations.h.in ${CORE_BIN_INC}/operations.h)
configure_file(${CORE_SRC_INC}/subsystems.h.in ${CORE_BIN_INC}/subsystems.h)

set(OBJ_LIST ${OBJ_LIST} PARENT_SCOPE)
set(EXT_LIBS ${EXT_LIBS} PARENT_SCOPE)
