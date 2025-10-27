#!/bin/sh

set -u

error=0
res=0

#
# Check if the ELE Daemon is present
# If not active, exit with an error
#
if [ -e /etc/systemd/system/nvm_daemon.service ]; then
  res=$(systemctl is-active nvm_daemon)
  if [ "${res}" != "active" ]; then
    echo "NVM Daemon is not active"
    exit 1
  fi
fi

if [ -z ${VALGRIND+x} ]; then
  eval "$*"
else
  valgrind --undef-value-errors=no --error-exitcode=2 --suppressions=./scripts/valgrind.supp $*
fi
error=$?

exit ${error}
