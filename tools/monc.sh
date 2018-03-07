#!/bin/sh

if [ $# -lt 1 ]; then
	echo "specify VE number" 1>&2
        exit 1
fi

VENUM=${1}

# ATB
./mmio_tool -f /dev/ve$VENUM -b 2 -w -a 0x00080000 -d 0x0000000000000C00
# PSW
./mmio_tool -f /dev/ve$VENUM -b 2 -w -a 0x00001000 -d 0x0000000000000000
# ATBD
./mmio_tool -f /dev/ve$VENUM -b 2 -w -a 0x00090000 -d 0x0000000000000003
# IC
./mmio_tool -f /dev/ve$VENUM -b 2 -w -a 0x00001010 -d 0x0000000000000000
# MONC(TRAP
./mmio_tool -f /dev/ve$VENUM -b 2 -w -a 0x00000000 -d 0x3F80000000000000
# EXS
./mmio_tool -f /dev/ve$VENUM -b 2 -w -a 0x00001008 -d 0x0000000000000006
