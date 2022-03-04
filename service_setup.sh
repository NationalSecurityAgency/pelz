#! /usr/bin/env bash

install=false;
uninstall=false;

while getopts iud: flag
do
  case "${flag}" in
    i) install=true;;
    u) uninstall=true;;
  esac
done

PREFIX="/usr/local"
SERVICE_DIR="/etc/systemd/system"

if $install
then
  touch "$SERVICE_DIR/pelz.service"
  echo "[Unit]" > "$SERVICE_DIR/pelz.service"
  echo "Description=PELZ Crypto Service" >> "$SERVICE_DIR/pelz.service"
  echo "After=network.target" >> "$SERVICE_DIR/pelz.service"
  echo "">> "$SERVICE_DIR/pelz.service"
  echo "[Service]" >> "$SERVICE_DIR/pelz.service"
  echo "Type=simple" >> "$SERVICE_DIR/pelz.service"
  echo "ExecStart=$PREFIX/bin/pelz" >> "$SERVICE_DIR/pelz.service"
  echo "" >> "$SERVICE_DIR/pelz.service"
  echo "[Install]" >> "$SERVICE_DIR/pelz.service"
  echo "WantedBy=multi-user.target" >> "$SERVICE_DIR/pelz.service"
  chmod 755 "$SERVICE_DIR/pelz.service"
  systemctl enable pelz.service
  systemctl start pelz.service
  echo "Service Startup Complete"
elif $uninstall
then
  systemctl disable pelz.service
  systemctl stop pelz.service
  rm -f "$SERVICE_DIR/pelz.service"
  echo "Service Teardown Complete"
else
  echo "Invalid commands provided."
fi
