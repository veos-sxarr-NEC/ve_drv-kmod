#!/bin/sh

if [ $# -lt 1 ]; then
	echo "specify VE number" 1>&2
	exit 1
fi

VENUM=${1}

./mmio_tool -f /dev/ve$VENUM -b 2 -w -a 0x014200b8 -d 0x0000000000001000 
./mmio_tool -f /dev/ve$VENUM -b 2 -w -a 0x014000c8 -d 0x0200000000000000

