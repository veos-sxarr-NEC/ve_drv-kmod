/*
 * Aurora Vector Engine Driver
 *
 * Copyright (C) 2020 NEC Corporation
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * @file ve_drv_ve3.h
 * @brief VE3-dependent part of VE driver header
 */

#ifndef VE_DRV_H_INCLUDE_
# error "Never use <ve_drv_ve3.h> directly; include <ve_drv.h> instead."
#endif

#ifndef VE_DRV_VE3_H_INCLUDE_
#define VE_DRV_VE3_H_INCLUDE_

#define VE_DRV_ARCH_NAME_VE3 "ve3"

/**
 * @brief VE node state enum
 */
enum ve_state {
	VE_ST_NOT_DEFINE0,	/*!< non defined state */
	VE_ST_AVAILABLE,	/*!< Available state */
	VE_ST_ONLINE=VE_ST_AVAILABLE, /*!< Available state */
	VE_ST_NOT_DEFINE1,	/*!< non defined state */
	VE_ST_MAINTENANCE,	/*!< Maintenance state */
	VE_ST_UNAVAILABLE,	/*!< Unavailable state */
};

/*
 * Offset and size information for mmap
 *
 *  offset
 *  0            +------------------+ VEDRV_VE3_MAP_BAR4_OFFSET
 *               | BAR4 (8MB)       |
 *         +BAR4 +------------------+
 *               | RFU (not in use) |
 *  128M         +------------------+ VEDRV_VE3_MAP_BAR2_OFFSET       800 0000ULL
 *               | BAR2 (64MB)      |
 *         +BAR2 +------------------+
 *               | RFU (not in use) |
 *  128M+2G      +------------------+ VEDRV_VE3_MAP_BAR0_OFFSET      8800 0000ULL
 *               | BAR0             |
 *  128M+2G+BAR0 +------------------+
 *               |                  |
 *  128M+2G+128G +------------------+                             20 8800 0000ULL
 *               |                  |
 *  128M+2G+256G +------------------+                             40 8800 0000ULL
 */
#define VEDRV_VE3_MAP_BAR4_OFFSET	(0x00000000ULL)
#define VEDRV_VE3_MAP_BAR2_OFFSET	(0x08000000ULL)
#define VEDRV_VE3_MAP_BAR0_OFFSET	(VEDRV_VE3_MAP_BAR2_OFFSET + 0x80000000ULL)

/*
 * SVR Mapping offsets from BAR23
 *
 * offset
 *     0 +------------------+
 *       | Core  0 User Reg |
 *  512K +------------------+
 *       | Core  0 Sys  Reg |
 *    1M +------------------+
 *       | Core  1 User Reg |
 *  1.5M +------------------+
 *       | Core  1 Sys  Reg |
 *  2.0M +------------------+
 *               ...
 * 31.5M +------------------+
 *       | Core 31 Sys  Reg |
 * 32.0M +------------------+
 *       |  Sys Common Reg  |
 * 34.0M +------------------+
 *       | Reserved         |
 * 64.0M +------------------+
 */

/* Register offsets */
#define VEDRV_VE3_PCI_BAR2_UREG_OFFSET	(0x0000000)	/*!<
							 * offset of user
							 * registers in BAR2
							 */
#define VEDRV_VE3_PCI_BAR2_UREG_SIZE	(0x0080000)	/*!<
							 * size of user
							 * registers in BAR2
							 */
#define VEDRV_VE3_PCI_BAR2_SREG_OFFSET	VEDRV_VE3_PCI_BAR2_UREG_SIZE	/*<!
							 * offset of system
							 * registers in BAR2
							 */
#define VEDRV_VE3_PCI_BAR2_SREG_SIZE	VEDRV_VE3_PCI_BAR2_UREG_SIZE	/*!<
							 * size of system
							 * registers in BAR2
							 */
#define VEDRV_VE3_PCI_BAR2_CREG_SIZE	(VEDRV_VE3_PCI_BAR2_UREG_SIZE + \
		VEDRV_VE3_PCI_BAR2_SREG_SIZE)	 /*!<
						  * size of core registers
						  */
#define VEDRV_VE3_PCI_BAR2_SCR_OFFSET	(0x2000000)	/*!< offset of
							 *   system common
							 *   registers in BAR2
							 */
#define VEDRV_VE3_PCI_BAR2_SCR_SIZE	(0x0200000)	/*!< size of
							 *   system common
							 *   registers in BAR2
							 */

/*
 * SVR Mapping offsets from BAR4
 *
 * offset
 *     0 +------------------+
 *       | Core  0 User Reg |
 *    4K +------------------+
 *       | Core  0 Sys  Reg |
 *   64K +------------------+
 *       | Core  1 User Reg |
 *   68K +------------------+
 *       | Core  1 Sys  Reg |
 *  128K +------------------+
 *               ...
 *       +------------------+
 *       | Core 31 Sys  Reg |
 *  2.0M +------------------+
 *       |  Sys Common Reg  |
 *  3.0M +------------------+
 *       | Reserved         |
 *  8.0M +------------------+
 *
 */
/* Register offsets */
#define VEDRV_VE3_PCI_BAR4_UREG_OFFSET	(0x00000)	/*!<
							 * offset of user
							 * registers in BAR4
							 */
#define VEDRV_VE3_PCI_BAR4_UREG_SIZE	(0x1000)	/*!<
							 * sixe of user
							 * registers in BAR4
							 */
#define VEDRV_VE3_PCI_BAR4_SREG_OFFSET	VEDRV_VE3_PCI_BAR4_UREG_SIZE	/*!<
							 * offset of system
							 * registers in BAR4
							 */
#define VEDRV_VE3_PCI_BAR4_SREG_SIZE	(0xf000)	/*!<
							 * size of system
							 * registers in BAR4
							 */
#define VEDRV_VE3_PCI_BAR4_CREG_SIZE	(VEDRV_VE3_PCI_BAR4_UREG_SIZE + \
		VEDRV_VE3_PCI_BAR4_SREG_SIZE)	 /*!<
						  * size of core registers
						  */
#define VEDRV_VE3_PCI_BAR4_SCR_OFFSET	(0x200000)	/*!< offset of
							 *   system common
							 *   registers in BAR4
							 */
#define VEDRV_VE3_PCI_BAR4_SCR_SIZE	(0x100000)	/*!< size of
							 *   system common
							 *   registers in BAR4
							 */

#define VEDRV_IRQ_TYPE_VE3 (0x3004556) /* 'V' 'E' '\0' 3 */
/**
 * INTVEC register
 *    bit|  63  ..  ..  32|  31  ..  .. ..  00|
 *-------+----------------+-------------------+
 * WORD 0|       Reserved | #31..(core#N).. #0|
 * WORD 1|  PCI exception |   0   0  .. .|PDMA|
 * WORD 2| #63  ..      UDMA#N   ..         #0|
 * WORD 3|  VE card fault |#31(core#N fault)#0|
 */
/**
 * @brief indicates interrupt vector (INTVEC)
 */
struct ve3_wait_irq {
	uint64_t ve_wait_irq_type;/* shall be VEDRV_IRQ_TYPE_VE3 */
	uint64_t intvec[4];
};

#endif /*VE_DRV_VE3_H_INCLUDE_*/
