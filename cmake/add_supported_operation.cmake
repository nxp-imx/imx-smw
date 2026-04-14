function(add_supported_operation name)
    string(TOUPPER ${name} u_name)

    get_property(names GLOBAL PROPERTY PROP_SUPPORTED_OPERATIONS)
    string(APPEND names "\t${u_name},\n")
    set_property(GLOBAL PROPERTY PROP_SUPPORTED_OPERATIONS ${names})
endfunction()
