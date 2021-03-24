#!/bin/bash
set -e

function usage()
{
    cat << EOF

    ************************************************
    * Usage of Security Middleware Coverity script *
    ************************************************

    Script is preparing the Security Middelware project targets
    to be analyzed by coverity (built in debug mode).
    No need to build the project coverity will do it.
    Then it call coverity script to do the code analysis.

    $(basename "$0") <arch>
      <arch> : Mandatory architecture aarch32 or aarch64

EOF
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
fi

arch="$1"

# Define local variable used in coverity script and yaml
compiler="${arch}-none-linux-gnu-gcc"
coverity_yaml="./tools/coverity/config/stec/smw_${arch}.yml"

cd "$bamboo_build_working_directory"/smw

build_debug=build.${arch}_deb

# Delete previous builds
rm -rf "${build_debug}"

#
# Configure, build and package Debug build of all targets
#
eval "./scripts/smw_configure.sh ${build_debug} ${arch}"
eval "./scripts/smw_build.sh configure out=${build_debug} debug verbose=4"

cd "$bamboo_build_working_directory"

#
# Create a copy of the Coverity Yaml script and replace the
# compiler and build output directory
#

eval "cp ./tools/coverity/config/stec/smw.yml ${coverity_yaml}"

sed -i "s|REPLACE_COMPILER|${compiler}|" "${coverity_yaml}"
sed -i "s|REPLACE_BUILD_DIR|${build_debug}|" "${coverity_yaml}"

#
# Set environment variable used by coverity scripts
#
BASE_DIR=$PWD

eval "./tools/coverity-agent/coverity_scan4.sh \
    --config ${coverity_yaml} \
    --coverity-dir $bamboo_capability_coveritydir_201909 \
    --source-path ./smw \
    --commands-path ./smw"
