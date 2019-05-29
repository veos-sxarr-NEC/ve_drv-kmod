/*
 * Aurora Vector Engine Driver
 *
 * Copyright (C) 2014 NEC Corporation
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
 * @file ve_drv.h
 * @brief VE driver header for userspace program and kernel module
 */

#ifndef VE_DRV_H_INCLUDE_
#define VE_DRV_H_INCLUDE_

#ifndef __KERNEL__
#include <stdint.h>
#include <sys/types.h>
#include <vp.h>
#else
#include "vp.h"
#endif

#define VEDRV_ABI_VERSION	(101)

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
#define VEDRV_MAP_BAR3_OFFSET	(0x00000000)
#define VEDRV_MAP_BAR2_OFFSET	(0x10000000)
#define VEDRV_MAP_BAR0_OFFSET	(0x20000000)

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
#define PCI_BAR2_UREG_OFFSET	(0x0000000)	/*<! offset of user registers */
#define PCI_BAR2_UREG_SIZE	(0x0080000)	/*<! size of user registers */
#define PCI_BAR2_SREG_OFFSET	PCI_BAR2_UREG_SIZE	/*<!
							 * offset of
							 * system registers
							 */
#define PCI_BAR2_SREG_SIZE	PCI_BAR2_UREG_SIZE	/*<!
							 * size of
							 * system registers
							 */
#define PCI_BAR2_CREG_SIZE	(PCI_BAR2_UREG_SIZE + \
		PCI_BAR2_SREG_SIZE)		 /*<!
						  * size of core registers
						  */
#define PCI_BAR2_SCR_OFFSET	(0x1000000)	/*<! offset of
						 *   system common registers
						 */
#define PCI_BAR2_SCR_SIZE	(0x0200000)	/*<! size of
						 *   system common registers
						 */

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

/**
 * @brief VEOS state enum
 */
enum os_state {
	OS_ST_ONLINE,		/*!< Online state */
	OS_ST_OFFLINE,		/*!< Offline state*/
	OS_ST_INITIALIZING,	/*!< Initializing state */
	OS_ST_TERMINATING,	/*!< Terminating state */
};

enum pd_list {
	OS_LIST = 0,		/* for VEOS */
	TD_LIST,		/* for MMM, TD */
	NR_PD_LIST,
};

struct ve_vp {
	enum pd_list type;
	struct vp vp_info;
};

struct ve_vp_blk {
	enum pd_list type;
	struct vp_blk vp_info;
};

struct ve_vp_release {
	enum pd_list type;
	unsigned long addr;
};

struct ve_vp_blk_release {
	enum pd_list type;
	int npages;
	uint64_t *addr;
};

/**
 * @brief indicates MSI-X interrupt vector
 */
struct ve_wait_irq {
	uint64_t upper;		/*!< upper 64 bits of MSI-X interrupt vector */
	uint64_t lower;		/*!< lower 64 bits of MSI-X interrupt vector */
};

/**
 * @brief Used for ioctl VEDRV_CMD_ASSIGN_TASK
 */
struct ve_tid_core {
	pid_t tid;	/*!< VE task ID */
	int core_id;	/*!< VE core ID */
};

/**
 * @brief Used for VEDRV_CMD_WAIT_INTR
 */
struct ve_wait_irq_arg {
	struct ve_wait_irq bits;	/*!< Interrupt bits to wait for */
	struct timespec *timeout;	/*!< Timeout value */
};

/**
 * @brief Used for VEDRV_CMD_ASSIGN_CR
 */
struct ve_cr_assign {
	int cr_page_num;	/*!< CR page number */
	uid_t owner_uid;	/*!< CR owner UID */
};

/**
 * @brief Used for VEDRV_CMD_UNASSIGN_VEMEM
 */
struct ve_pcimem_assign {
	int pciatb_entry;	/*!< PCIATB entry number */
	uid_t owner_uid;	/*!< PCIATB entry owner UID */
};

/**
 * @brief Used for VEDRV_CMD_UNMAP
 */
struct ve_unmap {
	off_t offset;	/*!< Offset from top of VE mmap region */
	size_t size;	/*!< Size of unmap */
};

/**
 * @brief Used for VEDRV_CMD_HOST_PID
 */
struct ve_get_host_pid {
	pid_t host_pid;	/*!< The host pid for idntify the namespace */
	pid_t namespace_pid;	/*!< The namespace pid to be converted */
};

/* ioctl magic number */
#define VE_IOC_MAGIC	0xF5

/* product version */
#define VEDRV_CMD_UPDATE_FIRMWARE	_IO(VE_IOC_MAGIC, 0)
#define VEDRV_CMD_WAIT_INTR		_IOWR(VE_IOC_MAGIC, 1, \
						struct ve_wait_irq_arg)
#define VEDRV_CMD_WAIT_EXCEPTION	_IOW(VE_IOC_MAGIC, 2, uint64_t)
#define VEDRV_CMD_VHVA_TO_VSAA		_IOWR(VE_IOC_MAGIC, 3, struct ve_vp)
#define VEDRV_CMD_CREATE_TASK		_IOR(VE_IOC_MAGIC, 4, pid_t)
#define VEDRV_CMD_DELETE_TASK		_IOR(VE_IOC_MAGIC, 5, pid_t)
#define VEDRV_CMD_ASSIGN_TASK		_IOR(VE_IOC_MAGIC, 6, \
						struct ve_tid_core)
#define VEDRV_CMD_UNASSIGN_TASK		_IOR(VE_IOC_MAGIC, 7, pid_t)
#define VEDRV_CMD_ASSIGN_CR		_IOR(VE_IOC_MAGIC, 8, \
						struct ve_cr_assign)
#define VEDRV_CMD_UNASSIGN_CR		_IOR(VE_IOC_MAGIC, 9, \
						struct ve_cr_assign)
#define VEDRV_CMD_ASSIGN_VEMEM		_IOR(VE_IOC_MAGIC, 10, \
					     struct ve_pcimem_assign)
#define VEDRV_CMD_UNASSIGN_VEMEM	_IOR(VE_IOC_MAGIC, 11, \
					     struct ve_pcimem_assign)
#define VEDRV_CMD_UNMAP			_IOR(VE_IOC_MAGIC, 12, struct ve_unmap)
#define VEDRV_CMD_RST_EXSRAR_MEM	_IOR(VE_IOC_MAGIC, 13, int)
#define VEDRV_CMD_VHVA_TO_VSAA_PIN_DOWN	_IOWR(VE_IOC_MAGIC, 14, struct ve_vp)
#define VEDRV_CMD_RELEASE_PD_PAGE	_IOR(VE_IOC_MAGIC, 15, \
						struct ve_vp_release)
#define VEDRV_CMD_RELEASE_PD_PAGE_ALL	_IOR(VE_IOC_MAGIC, 16, \
						struct ve_vp_release)
#define VEDRV_CMD_DELETE_ALL_TASK	_IO(VE_IOC_MAGIC, 17)
#define VEDRV_CMD_RST_INTR_COUNT	_IOR(VE_IOC_MAGIC, 18, uint64_t)
#define VEDRV_CMD_VE_RESET		_IOR(VE_IOC_MAGIC, 19, uint64_t)
#define VEDRV_CMD_REVIVE_TASK		_IOR(VE_IOC_MAGIC, 20, pid_t)
#define VEDRV_CMD_HOST_PID		_IOR(VE_IOC_MAGIC, 21, struct ve_get_host_pid)
#define VEDRV_CMD_VHVA_TO_VSAA_BLK	_IOWR(VE_IOC_MAGIC, 22, struct ve_vp_blk)
#define VEDRV_CMD_VHVA_TO_VSAA_BLK_PIN_DOWN _IOWR(VE_IOC_MAGIC, 23, struct ve_vp_blk)
#define VEDRV_CMD_RELEASE_PD_PAGE_BLK	_IOR(VE_IOC_MAGIC, 24, \
						struct ve_vp_blk_release)
#define VEDRV_CMD_COUNT_PD_PAGE_ALL	_IOR(VE_IOC_MAGIC, 25, \
						struct ve_vp_release)
#endif /*VE_DRV_H_INCLUDE_*/
