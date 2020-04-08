function(add_component name prefix_id return_export list_id list_export list_name list_func)
    string(TOLOWER ${name} l_name)
    string(TOUPPER ${name} u_name)

    message(STATUS "Enable ${u_name}")

    set(func smw_${l_name}_get_func)
    set(enum ${prefix_id}_${u_name})

    list(APPEND ${list_id} "${enum},")
    string(REPLACE ";" "\n\t" ${list_id} "${${list_id}}")
    set(${list_id} ${${list_id}} PARENT_SCOPE)

    list(APPEND ${list_export} "${${return_export}}${func}(void);\n")
    string(REPLACE ";\n;" ";\n" ${list_export} "${${list_export}}")
    set(${list_export} ${${list_export}} PARENT_SCOPE)

    list(APPEND ${list_name} "[${enum}] = \"${u_name}\"")
    string(REPLACE ";" ",\n\t" ${list_name} "${${list_name}}")
    set(${list_name} ${${list_name}} PARENT_SCOPE)

    list(APPEND ${list_func} "[${enum}] = ${func}")
    string(REPLACE ";" ",\n\t" ${list_func} "${${list_func}}")
    set(${list_func} ${${list_func}} PARENT_SCOPE)
endfunction()
