#!/bin/sh

if [ $# -lt 1 ]; then
	echo "$#"
	echo "specify VE number" 1>&2
	exit 1
fi

VENUM=${1}

./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01400300
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01400308
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01400310
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01400318
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01400380
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01400400
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01400500
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01400600
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01400700
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01460080
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01460090
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01461080
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01461090
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01488420
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x01490100
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x000000000148CF80
./mmio_tool -f /dev/ve$VENUM -b 2 -r -a 0x000000000148CF88
