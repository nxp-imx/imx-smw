#!/bin/sh

setup_nvm_daemon() {
  #
  # Check if the ELE Daemon is present
  #
  if [ -e /etc/systemd/system/nvm_daemon.service ]; then
    if [ -e /run/systemd/system/nvm_daemon.service.d/override.conf ]; then
      if (systemctl -q is-active nvm_daemon)
      then
        echo "nvm daemon is running"
      else
        systemctl start nvm_daemon
        exit_on_fail "nvm_daemon-start"
      fi
      return
    fi

    # If active, stop it
    if (systemctl -q is-active nvm_daemon)
    then
      echo "stop nvm daemon"
      systemctl stop nvm_daemon
      exit_on_fail "nvm_daemon-stop"
    fi

    # Create a new nvmd configuration
    echo "NVMD_STORAGE_DIRNAME=/tmp/ele/" > /tmp/nvmd.conf
    echo "NVMD_STORAGE_FILENAME=/tmp/ele/ele_nvm_master" >> /tmp/nvmd.conf
    echo "NVMD_MU_SESSION_FLAG=0x80" >> /tmp/nvmd.conf

    mkdir -p /run/systemd/system/nvm_daemon.service.d
    cat <<EOF > /run/systemd/system/nvm_daemon.service.d/override.conf
[Service]
EnvironmentFile=
EnvironmentFile=/tmp/nvmd.conf
EOF

    systemctl daemon-reload
    systemctl start nvm_daemon
    exit_on_fail "nvm_daemon-start"

    res=$(systemctl is-active nvm_daemon)
    if [ "${res}" != "active" ]; then
      echo "NVM Daemon start failure"
      systemctl -l status nvm_daemon
      exit 1
    fi
  fi
}

cleanup_nvm_daemon() {
  if [ -e /tmp/ele ]; then
    systemctl stop nvm_daemon
    rm -rf /run/systemd/system/nvm_daemon.service.d
    rm -rf /tmp/ele
    systemctl daemon-reload
  fi
}
