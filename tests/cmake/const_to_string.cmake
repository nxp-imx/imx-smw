#
# This script must be called with the following parameters:
# PREFIX: [optiona] prefix of the constants to extract
# INPUT: filename where is the constant to extract
# SRC: project source file template (configure_file)
# DST: project destination file (configure_file)
#
cmake_minimum_required(VERSION 3.5)

#
# conv_const_string() - build list of const to const/string table
# @infile: [Input] Input filename where are the constant values
# @outlist: [Output] String of CONST_TO_STRING items
#
# Function extracts all constant values from the input file and
# build a table of CONST_TO_STRING(const value).
# CONST_TO_STRING is a macro that must be already defined in the code.
#
function (conv_const_string infile outlist)
    set (extra_args ${ARGN})
    list(LENGTH extra_args extra_count)
    if (${extra_count} GREATER 0)
        list(GET extra_args 0 prefix)
    endif()

    file(STRINGS ${infile} myfile)

    set(list_status "\n")
    foreach(line ${myfile})
        if(line)
            string(REGEX MATCH "#define[\t ]+${prefix}[A-Za-z0-9_]+" fstr "${line}")
            if(NOT ${fstr} EQUAL "")
                string(SUBSTRING ${fstr} 7 -1 fstr)
                string(STRIP ${fstr} fstr)
                if(NOT ${fstr} EQUAL "")
                    string(REGEX MATCH "${prefix}[A-Za-z0-9_]+" fstr ${fstr})
                    if(NOT ${fstr} EQUAL "")
                        string(APPEND list_status "\tCONST_TO_STRING(${fstr}),\n")
                    endif()
                endif()
            endif()
        endif()
    endforeach()

    set(${${outlist}} ${list_status} PARENT_SCOPE)

endfunction()

conv_const_string(${INPUT} OUTPUT_LIST ${PREFIX})
configure_file(${SRC} ${DST} @ONLY)
