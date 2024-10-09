#!/bin/sh

set -u

error=0
res=0
conf_file=/etc/opt/smw/smw.conf
script_conf=/etc/opt/smw/smw_system_conf.sh

# Check if the ELE Daemon is present
# If not active, start it
#
if [ -e /etc/systemd/system/nvm_daemon.service ]; then
  res=$(systemctl is-active nvm_daemon)
  if [ "${res}" != "active" ]; then
    systemctl start nvm_daemon
    res=$(systemctl is-active nvm_daemon)
    if [ "${res}" != "active" ]; then
      echo "NVM Daemon start failure"
      systemctl -l status nvm_daemon
      exit 1
    fi
  fi
fi

# Update the smw.conf for the test purpose
if [ -e ${script_conf} ]; then
  # Save a copy of the original smw.conf
  cp ${conf_file} ${conf_file}.bak

  # Setup the database
  res=$(${script_conf} in=${conf_file} conf=setup database=/var/tmp/obj_db_pkcs11_test.dat)
  if [ "${res}" ]; then
    echo "${res}"
    exit 2
  fi

  # Setup the seco subsystem
  res=$(${script_conf} in=${conf_file} conf=seco id=0x504b3131 nonce=0x444546 replay=1000)
   if [ "${res}" ]; then
    echo "${res}"
    exit 2
  fi

  # Setup the ele subsystem
  res=$(${script_conf} in=${conf_file} conf=ele id=0x504b3131 nonce=0x444546)
   if [ "${res}" ]; then
    echo "${res}"
    exit 2
  fi
fi

eval "$*"
error=$?

if [ -e ${script_conf} ]; then
  # Restore the original smw.conf
  mv ${conf_file}.bak ${conf_file}
fi

exit ${error}
