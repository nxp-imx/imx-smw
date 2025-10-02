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

eval "$*"
error=$?

exit ${error}
