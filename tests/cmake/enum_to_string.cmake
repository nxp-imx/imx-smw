#
# This script must be called with the following parameters:
# ENUM: enumerate name to extract
# INPUT: filename where is the enumerate to extract
# SRC: project source file template (configure_file)
# DST: project destination file (configure_file)
#
cmake_minimum_required(VERSION 3.5)

#
# conv_enum_string() - build list of enum to enum/string table
# @enum: [Input] Enumerate name to extract from @infile
# @infile: [Input] Input filename where is the @enum
# @outlist: [Output] String of ENUM_TO_STRING items
#
# Function extracts all enumerate values from the @enum table and
# build a table of ENUM_TO_STRING(enum value).
# ENUM_TO_STRING is a macro that must be already defined in the code.
#
function (conv_enum_string enum infile outlist)
    file(STRINGS ${infile} myfile)

    foreach(line IN LISTS myfile)
        list(REMOVE_AT myfile 0)
        if (line)
            string(FIND ${line} "enum ${enum} {" found)
            if(NOT ${found} EQUAL -1)
               break()
            endif()
        endif()
    endforeach()

    if(${found} EQUAL -1)
        message(FATAL_ERROR "File ${infile} doesn't contain \"enum ${enum}\"")
    endif()

    set(list_status "\n")
    foreach(line ${myfile})
        if(line)
            if (line MATCHES "}")
                break()
            endif()
            string(REGEX MATCH "[A-Za-z0-9_]+" fstr ${line})
            string(APPEND list_status "\tENUM_TO_STRING(${fstr}),\n")
        endif()
    endforeach()

    set(${${outlist}} ${list_status} PARENT_SCOPE)

endfunction()

conv_enum_string(${ENUM} ${INPUT} OUTPUT_LIST)
configure_file(${SRC} ${DST} @ONLY)
