function(add_component implicit name prefix_id return_export list_id list_export list_name list_func)
    string(TOLOWER ${name} l_name)
    string(TOUPPER ${name} u_name)

    message(STATUS "Enable ${u_name}")

    if (${implicit} EQUAL 0)
        set(func smw_${l_name}_get_func)
    else()
        set(func NULL)
    endif()

    set(enum ${prefix_id}_${u_name})

    get_property(ids GLOBAL PROPERTY ${list_id})
    string(APPEND ids "\t${enum},\n")
    set_property(GLOBAL PROPERTY ${list_id} ${ids})

    if (${implicit} EQUAL 0)
        get_property(exports GLOBAL PROPERTY ${list_export})
        string(APPEND exports "${${return_export}}${func}(void);\n")
        set_property(GLOBAL PROPERTY ${list_export} ${exports})
    endif()

    get_property(names GLOBAL PROPERTY ${list_name})
    string(APPEND names "\t[${enum}] = \"${u_name}\",\n")
    set_property(GLOBAL PROPERTY ${list_name} ${names})

    get_property(funcs GLOBAL PROPERTY ${list_func})
    string(APPEND funcs "\t[${enum}] = ${func},\n")
    set_property(GLOBAL PROPERTY ${list_func} ${funcs})
endfunction()
