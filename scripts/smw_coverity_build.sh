#!/bin/bash
set -e

function usage()
{
    cat << EOF

    ******************************************************
    * Usage of Security Middleware Coverity build script *
    ******************************************************

    Script is cleaning first the SMW targets and then
    rebuild all targets configured in given directory.

    It is assumed that projects have been configured before calling
    this script and dependencies built as well.

    $(basename "$0") <dir>
      <dir> : Mandatory build directory

EOF
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
fi

# Clean build targets first
eval "cd $1 && make clean && cd .."

# Rebuild targets
eval "./scripts/smw_build.sh build out=$1"
