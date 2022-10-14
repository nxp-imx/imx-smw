#! /bin/sh

set -u

error=0
res=0

# Check if the ELE Daemon is present
# If not active, start it
#
if [[ -e /etc/systemd/system/nvm_daemon.service ]]; then
  res=$(systemctl is-active nvm_daemon)
  if [[ ${res} != "active" ]]; then
    systemctl start nvm_daemon
    res=$(systemctl is-active nvm_daemon)
    if [[ ${res} != "active" ]]; then
      echo "NVM Daemon start failure"
      systemctl -l status nvm_daemon
      exit 1
    fi
  fi
fi

eval "$@"
error=$?

if [[ -e /etc/systemd/system/nvm_daemon.service ]]; then
  res=$(systemctl is-active nvm_daemon)
  if [[ ${res} == "active" ]]; then
    systemctl stop nvm_daemon
    res=$(systemctl is-active nvm_daemon)
    if [[ ${res} == "active" ]]; then
      echo "NVM Daemon stop failure"
      systemctl -l status nvm_daemon
      error=1
    fi
  fi
fi

exit ${error}
