#!/bin/bash
MMIO_TOOL="./mmio_tool_ve3"
VALID_DMAATB_DIR=()
no_shift_base_addr=0

parse_dmaatb_dir () {
	local cnt=$1
	local dmaatb_dir=$2
	local psnum=0
	local jid=0
	local tmp=0
	local size=0
	local valid=0

	psnum=$((${dmaatb_dir} & 0xfffffff00000))
	if [ $no_shift_base_addr -eq 0 ]; then
		psnum=$((${psnum}>>20))
	fi

	jid=$((${dmaatb_dir} & 0xff000))
	jid=$((${jid}>>12))

	tmp=$((${dmaatb_dir} & 0x6))
	tmp=$((${tmp}>>1))
	if [ ${tmp} -eq 0 ]; then
		size="4K"
	elif [ ${tmp} -eq 1 ]; then
		size="2M"
	elif [ ${tmp} -eq 2 ]; then
		size="64M"
	elif [ ${tmp} -eq 3 ]; then
		size="256"
	else
		size="Invalid"
	fi

	tmp=$((${dmaatb_dir} & 0x1))
	if [ ${tmp} -eq 1 ]; then
		valid="Valid"
	else
		valid="Invalid"
	fi

	printf 'DIR[%2d] : %s 0x%-6x %-4d  %-3s  %s\n' \
			${cnt} ${dmaatb_dir} ${psnum} ${jid} ${size} ${valid}
}

show_dmaatb_dir () {
	local cnt=0
	local dmaatb_dir

	echo "DIR       RAW                PSNUM  JID   SIZE   VALID"
	echo "========================================================"
	sudo ${MMIO_TOOL} -f /dev/veslot${NODE} -b 2 \
		-r -a $((0x2000000 + 0x0C0000)) -s 0x800 | while read line
	do
		echo ${line} | grep -v "0x0000000000000000" > /dev/null 2>&1
		if [ $? -eq 0 ]; then
			dmaatb_dir=`echo ${line} | awk '{print $2}'`
			parse_dmaatb_dir ${cnt} ${dmaatb_dir}
			#echo "DIR[${cnt}] : ${dmaatb_dir}"
		fi
		cnt=$((${cnt} + 1))
	done
}

check_valid_dir () {
	local tmp=0
	local cnt=0
	local target_dir=()

	while read line
	do
		tmp=`echo ${line} | awk '{print $2}'`
		tmp=$((${tmp} & 0x1))
		if [ ${tmp} -eq 1 ]; then
			target_dir+=(${cnt})
		fi
		cnt=$((${cnt} + 1))
	done

	echo ${target_dir[*]}
}

parse_dmaatb_entry () {
	local dmaatb_entry=$1
	local entry=$2
	local pba=0
	local Type=0
	local winh=0
	local cache_bypass=0
	local tmp=0

	pba=$((${dmaatb_entry} & 0xffffffffff000))
	if [ $no_shift_base_addr -eq 0 ]; then
		pba=$((${pba}>>12))
	fi

	tmp=$((${dmaatb_entry} & 0xe00))
	tmp=$((${tmp}>>9))
	case ${tmp} in
		0 ) Type="VERAA" ;; #VE register absolete address
		2 ) Type="VHSAA" ;;
		4 ) Type="VERAAc" ;; #VE register absolete address, for control registers
		5 ) Type="VECRAA" ;;
		6 ) Type="VEMAA" ;;
		* ) Type="INVALID" ;;
	esac


	tmp=$((${dmaatb_entry} & 0x4))
	tmp=$((${tmp}>>3))
	if [ ${tmp} -eq 1 ]; then
		winh="No"
	else
		winh="Yes"
	fi

	tmp=$((${dmaatb_entry} & 0x2))
	tmp=$((${tmp}>>2))
	if [ ${tmp} -eq 1 ]; then
		cache_bypass="Yes"
	else
		cache_bypass="No"
	fi

	printf '%-5d %s 0x%-8x %7s %9s %6s\n' \
		${entry} ${dmaatb_entry} ${pba} ${Type} ${winh} ${cache_bypass}
}

show_dmaatb_entry () {
	local specified_dir=$1
	local target_dir=()
	local tmp=0
	local cnt=-1
	local offset=0
	local invalid=0

	if [ ${specified_dir} -eq -1 ]; then
		target_dir=`sudo ${MMIO_TOOL} -f /dev/veslot${NODE} -b 2 \
			-r -a $((0x2000000 + 0x0C0000)) -s 0x800 | check_valid_dir`
	else
		target_dir=(${specified_dir})
	fi

	#echo "Valid Dirs = ${target_dir[*]}"

	for I in ${target_dir[*]}
	do
		echo "DIR[${I}]"
		echo "ENTRY                RAW PBA           TYPE WRITEABLE BYPASS"
		echo "============================================================"
		sudo ${MMIO_TOOL} -f /dev/veslot${NODE} -b 2 -r \
			-a `printf '0x%x' $((0x2000000 + 0x040000 + 0x800 * ${I}))` \
			-s 0x800 | while read line
		do
			cnt=$((${cnt} + 1))
			tmp=`echo ${line} | awk '{print $2}'`
			if [ -z ${tmp} ]; then
				continue
			fi
			invalid=$((${tmp} & 0x01))
			if [ ${invalid} -eq 1 ]; then
				continue
			fi
			parse_dmaatb_entry ${tmp} ${cnt}
		done
	done
}

parse_atb_dir () {
	local cnt=-1
	local corenum=$1
	local dir=""
	local ps=0
	local size=""
	local valid=""

	sudo ${MMIO_TOOL} -f /dev/veslot${NODE} -b 2 -r \
		-a $((0x10000 + 0x80000 + 0x100000 * ${corenum})) \
		-s 0x100 | while read line
	do
		cnt=$((${cnt} + 1))
		dir=`echo ${line} | awk '{print $2}'`

		valid=$((${dir} & 0x1))
		if [ ${valid} -eq 0 ]; then
			continue
		fi

		ps=$((${dir} & 0xffffe0000000))
		if [ $no_shift_base_addr -eq 0 ]; then
			ps=$((${ps}>>29))
		fi

		size=$((${dir} & 0x6))
		size=$((${size}>>1))

		case ${size} in
			1 ) size="2MB" ;;
			2 ) size="64MB" ;;
			* ) size="Invalid" ;;
		esac

		printf '%3d %s 0x%-5x %7s\n' ${cnt} ${dir} ${ps} ${size}
	done

}

show_atb_dir () {
	local cnt=0
	local cores=()
	local sores_enable=""
	local ve_max_core=16
	local cnt=0
	local tmp=0

	sores_enable=`cat /sys/\`udevadm info -q path /dev/veslot${NODE}\`/cores_enable`

	while [ ${cnt} -lt ${ve_max_core} ]
	do
		tmp=$((${sores_enable} & 1 << ${cnt}))
		if [ ${tmp} -ne 0 ]; then
			echo "CORE[${cnt}]"
			echo "DIR RAW                PS         SIZE"
			echo "======================================"
			parse_atb_dir ${cnt}
		fi

		cnt=$((${cnt} + 1))

	done
}

parse_atb_entry_for_each_dir () {
	local entry=$1
	local entry_num=$2
	local pb=0
	local Type=""
	local tmp=0
	local writable=""
	local bypass=""

	pb=$((${entry} & 0xffffffe00000))
	if [ $no_shift_base_addr -eq 0 ]; then
		pb=$((${pb}>>21))
	fi

	tmp=$((${entry} & 0x0e00))
	tmp=$((${tmp}>>9))
	if [ ${tmp} -ne 6 ]; then
		Type="Invalid"
	else
		Type="ATB"
	fi

	tmp=$((${entry} & 0x4))
	tmp=$((${tmp}>>2))
	if [ ${tmp} -eq 0 ]; then
		writable="Yes"
	else
		writable="No"
	fi

	tmp=$((${entry} & 0x2))
	tmp=$((${tmp}>>1))
	if [ ${tmp} -eq 1 ]; then
		bypass="Yes"
	else
		bypass="No"
	fi

	printf '%5d %s 0x%-7x %7s %9s %6s\n' \
			${entry_num} ${entry} ${pb} ${Type} ${writable} ${bypass}
}

parse_atb_entry () {
	local corenum=$1
	local cnt=-1
	local valid_dir=()
	local tmp=0
	local atb_dir_num=32
	local invalid=0
	local sysreg=$((0x80000 + 0x100000 * ${corenum}))

	valid_dir=`sudo ${MMIO_TOOL} -f /dev/veslot${NODE} -b 2 \
			-r -a $((0x10000 + 0x80000 + 0x100000 * ${corenum})) \
			-s 0x100 | check_valid_dir`



	for I in ${valid_dir}
	do
		echo "DIR[${I}]"
		echo "ENTRY RAW                PB           TYPE WRITEABLE BYPASS"
		echo "==========================================================="
		sudo ${MMIO_TOOL} -f /dev/veslot${NODE} -b 2 -r \
			-a `printf '0x%x' $((${sysreg} + 0x800 * ${I}))` \
			-s 0x800 | while read line
		do
			cnt=$((${cnt} + 1))
			tmp=`echo ${line} | awk '{print $2}'`
			if [ -z ${tmp} ]; then
				continue
			fi
			invalid=$((${tmp} & 0x01))
			if [ ${invalid} -eq 1 ]; then
				continue
			fi
			parse_atb_entry_for_each_dir ${tmp} ${cnt}
		done
	done

}

show_atb_entry () {
	local ve_max_core=16
	local cnt=0
	local tmp=0
	local target_core=$1

	cores_enable=`cat /sys/\`udevadm info -q path /dev/veslot${NODE}\`/cores_enable`

	if [ ${target_core} -eq -1 ]; then
		while [ ${cnt} -lt ${ve_max_core} ]
		do
			tmp=$((${cores_enable} & 1 << ${cnt}))
			if [ ${tmp} -ne 0 ]; then
				echo "CORE[${cnt}]"
				parse_atb_entry ${cnt}
			fi

			cnt=$((${cnt} + 1))
		done
	else
		tmp=$((${cores_enable} & 1 << ${target_core}))
		if [ ${tmp} -ne 0 ]; then
			echo "CORE[${target_core}]"
			parse_atb_entry ${target_core}
		fi
	fi
}

DMAATB=0
ATB=0
DIR=0
ENTRY=0
NODE=0
SHOWN_DIR=-1
SHOWN_CORE=-1

# -D : DMAATB
# -A : ATB
# -d : dir
# -e : entry
# -N : VE slot number
# -E : Directory which is going to be shown
# -c : Core which is going to be shown

function usage () {
echo "
Options:
	-D : Show DMAATB 
	-A : Show ATB 
	-d : Show directory 
	-e : Show entry 
	-N : Specifi Node 
	-E : Specify Dir to be shown 
	-c : Specify core to be shown
        -n : No shift base address"
echo "
Usage : -D {-d|-e [-E]}
        -A {-d|-e [-c]}
"
}

while getopts hDAdeN:E:c:n OPT
do
	case $OPT in
		"D" ) DMAATB=1 ;;
		"A" ) ATB=1 ;;
		"d" ) DIR=1 ;;
		"e" ) ENTRY=1 ;;
		"N" ) NODE="$OPTARG" ;;
		"E" ) SHOWN_DIR="$OPTARG" ;;
		"c" ) SHOWN_CORE="$OPTARG" ;;
		"n" ) no_shift_base_addr=1;;
		"h" ) usage ;;
	esac
done

if [ ${DMAATB} -eq 1 ]; then
	if [ ${DIR} -eq 1 ]; then
		show_dmaatb_dir
	fi
	if [ ${ENTRY} -eq 1 ]; then
		show_dmaatb_entry ${SHOWN_DIR}
	fi
fi

if [ ${ATB} -eq 1 ]; then
	if [ ${DIR} -eq 1 ]; then
		show_atb_dir
	fi
	if [ ${ENTRY} -eq 1 ]; then
		show_atb_entry ${SHOWN_CORE}
	fi
fi
