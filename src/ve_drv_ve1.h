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
 * @file ve_drv_ve1.h
 * @brief VE1-dependent part of VE driver header
 */

#ifndef VE_DRV_H_INCLUDE_
# error "Never use <ve_drv_ve1.h> directly; include <ve_drv.h> instead."
#endif

#ifndef VE_DRV_VE1_H_INCLUDE_
#define VE_DRV_VE1_H_INCLUDE_

#define VE_DRV_ARCH_NAME_VE1 "ve1"

/**
 * @brief VE node state enum
 */
enum ve_state {
	VE_ST_UNINITIALIZED,	/*!< Uninitialized state */
	VE_ST_ONLINE,		/*!< Online state */
	VE_ST_OFFLINE,		/*!< Offline state*/
	VE_ST_MAINTENANCE,	/*!< Maintenance state */
	VE_ST_UNAVAILABLE,	/*!< Unavailable state */
};

/*
 * Offset and size information for mmap
 *
 *      offset
 *          0 +------------------+
 *            | BAR3             |
 *    0M+BAR3 +------------------+
 *            | RFU (not in use) |
 *       256M +------------------+
 *            | BAR2             |
 *  256M+BAR2 +------------------+
 *            | RFU (not in use) |
 *       512M +------------------+
 *            | BAR0             |
 *  512M+BAR0 +------------------+
 */
#define VEDRV_VE1_MAP_BAR3_OFFSET	(0x00000000ULL)
#define VEDRV_VE1_MAP_BAR2_OFFSET	(0x10000000ULL)
#define VEDRV_VE1_MAP_BAR0_OFFSET	(0x20000000ULL)

/*
 * SVR Mapping offsets from BAR2
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
 * 15.5M +------------------+
 *       | Core 15 Sys  Reg |
 * 16.0M +------------------+
 *       | Common Reg       |
 * 18.0M +------------------+
 *       | Reserved         |
 * 32.0M +------------------+
 */

/* Register offsets */
#define VEDRV_VE1_PCI_BAR2_UREG_OFFSET	(0x0000000)	/*!<
							 * offset of user
							 * registers
							 */
#define VEDRV_VE1_PCI_BAR2_UREG_SIZE	(0x0080000)     /*!<
							 * size of user
							 * registers
							 */
#define VEDRV_VE1_PCI_BAR2_SREG_OFFSET	VEDRV_VE1_PCI_BAR2_UREG_SIZE	/*!<
							 * offset of system
							 * registers
							 */
#define VEDRV_VE1_PCI_BAR2_SREG_SIZE	VEDRV_VE1_PCI_BAR2_UREG_SIZE	/*!<
							 * size of system
							 * registers
							 */
#define VEDRV_VE1_PCI_BAR2_CREG_SIZE	(VEDRV_VE1_PCI_BAR2_UREG_SIZE + \
		VEDRV_VE1_PCI_BAR2_SREG_SIZE)	 /*!<
						  * size of core registers
						  */
#define VEDRV_VE1_PCI_BAR2_SCR_OFFSET	(0x1000000)	/*!< offset of
							 *   system common
							 *   registers
							 */
#define VEDRV_VE1_PCI_BAR2_SCR_SIZE	(0x0200000)	/*!< size of
							 *   system common
							 *   registers
							 */

#define VEDRV_IRQ_TYPE_VE1 (0x1004556) /* 'V' 'E' '\0' 1 */
/**
 * @brief indicates interrupt vector (INTVEC)
 */
struct ve1_wait_irq {
	uint64_t ve_wait_irq_type;/* shall be VE_DRV_IRQ_TYPE_VE1 */
	uint64_t upper;
	uint64_t lower;
};

/**
 * @brief MSI-X interrupt vector compatible with ve_drv v1 and v2 for VE1.
 */
struct ve1_compat_wait_irq {
	uint64_t upper;
	uint64_t lower;
};

/**
 * @brief argument of VEDRV_CMD_COMPAT_VE1_WAIT_INTR
 *
 * VEDRV_CMD_COMPAT_VE1_WAIT_INTR = VEDRV_CMD_WAIT_INTR in v1 and v2 for VE1.
 */
struct ve1_compat_wait_irq_arg {
	struct ve1_compat_wait_irq bits;/*!< Interrupt bits to wait for */
	struct timespec *timeout;	/*!< Timeout value */
};

/* VE1 ioctl commands */
#define VEDRV_CMD_VE1_UPDATE_FIRMWARE	_IO(VE_IOC_MAGIC, 0)
#define VEDRV_CMD_COMPAT_VE1_WAIT_INTR	_IOWR(VE_IOC_MAGIC, 1, \
						struct ve1_compat_wait_irq_arg)

#endif /*VE_DRV_VE1_H_INCLUDE_*/
