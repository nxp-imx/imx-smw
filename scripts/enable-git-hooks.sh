#! /bin/bash

set -e
set -u

: "${IGNORE_REPO:=0}"

HOOKS=(
    pre-commit
    pre-commit.d
    commit-msg
)

REALPATH="$(readlink -e "$0")"
BASEDIR="$(dirname "${REALPATH}")"
GIT_DIR="$( cd "${BASEDIR}/../" && git rev-parse --show-toplevel)"
HOOK_DIR="${GIT_DIR}/.git/hooks"

# Adapt hooks' symlinks depending on if we are in a "repo", or a bare git tree
REPO_TEST_PATH="${GIT_DIR}"
while true ; do
    if [ -e "${REPO_TEST_PATH}/.repo/manifest.xml" ] && [ "${IGNORE_REPO}" != 1 ] ; then
        echo "ERROR: This script is not meant to be used with \"repo\"." >&2
        exit 1
    fi
    if [[ "${REPO_TEST_PATH}" == "/" ]] ; then
        break
    fi
    REPO_TEST_PATH="$(readlink -f "${REPO_TEST_PATH}"/..)"
done

for HOOK in "${HOOKS[@]}" ; do
    if [ -e "${HOOK_DIR}/${HOOK}" ] ; then
        echo "WARNING: ${HOOK_DIR}/${HOOK} already exists. Skipping..." >&2
    else
        ln -s -f ../../scripts/git-hooks/"${HOOK}" "${HOOK_DIR}/"
        echo "Created symlink ${HOOK_DIR}/${HOOK}" >&2
    fi
done
