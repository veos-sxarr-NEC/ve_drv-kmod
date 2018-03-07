#!/bin/sh

sudo ./pci_sys_cmd.py 0x001c -r
#sudo sh -c "echo 1 > /sys/bus/pci/rescan"
