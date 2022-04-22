#!/bin/bash

if [[ "$EUID" -eq 0 ]]; then
  echo "This script should should not be run with superuser privileges !!!"
  exit 1
fi

./stop.sh

make clean
make &> /dev/null
if [ $? -eq 0 ]
then
  echo "Successfully make"
else
  echo "Could not make kernel object module "
  exit 1
fi

INTF=enp0s25

#sudo ifconfig $INTF promisc
sudo insmod ipsec_drop.ko

sudo dmesg --follow
