#!/bin/bash

INTF=enp0s25

#sudo ifconfig $INTF -promisc
sudo rmmod ipsec_drop
