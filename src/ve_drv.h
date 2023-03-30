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

#if defined(_VE_ARCH_VE3_)
#include <ve_drv_ve3.h>
#elif defined(_VE_ARCH_VE1_)
#include <ve_drv_ve1.h>
#endif

#define VEDRV_ABI_VERSION	(101)

#define VEDRV_ARCH_CLASS_NAME_MAX (8)

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
 * @brief MSI-X interrupt vector
 */
struct ve_wait_irq {
	uint64_t ve_irq_type;
	/* architecture-dependent */
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
	struct ve_wait_irq *bits;	/*!< Interrupt bits to wait for */
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


/**
 * @brief Used for VEDRV_CMD_REQEUST_OWNERSHIP/VEDRV_CMD_RELEASE_OWNERSHIP
 */
struct ve_ownership {
	int cmd;	/*!< The cmd is request or release*/
};



/* ioctl magic number */
#define VE_IOC_MAGIC	0xF5

/* product version */
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
#define VEDRV_CMD_VE_VE_RESET		_IOR(VE_IOC_MAGIC, 19, uint64_t)
#define VEDRV_CMD_REVIVE_TASK		_IOR(VE_IOC_MAGIC, 20, pid_t)
#define VEDRV_CMD_HOST_PID		_IOR(VE_IOC_MAGIC, 21, struct ve_get_host_pid)
#define VEDRV_CMD_VHVA_TO_VSAA_BLK	_IOWR(VE_IOC_MAGIC, 22, struct ve_vp_blk)
#define VEDRV_CMD_VHVA_TO_VSAA_BLK_PIN_DOWN _IOWR(VE_IOC_MAGIC, 23, struct ve_vp_blk)
#define VEDRV_CMD_RELEASE_PD_PAGE_BLK	_IOR(VE_IOC_MAGIC, 24, \
						struct ve_vp_blk_release)
#define VEDRV_CMD_COUNT_PD_PAGE_ALL	_IOR(VE_IOC_MAGIC, 25, \
						struct ve_vp_release)

#define VEDRV_CMD_OWNERSHIP	        _IOR(VE_IOC_MAGIC, 26,	\
						struct ve_ownership)

///****
#define VEDRV_CMD_NOTIFY_FAULT	        _IO(VE_IOC_MAGIC, 27)
#define VEDRV_CMD_GET_EXS_REG           _IOW(VE_IOC_MAGIC, 28, uint64_t)
#define VEDRV_CMD_COMPLETE_MEMCLEAR     _IO(VE_IOC_MAGIC, 29)
#define VEDRV_CMD_HANDLE_CLOCK_GATING   _IOR(VE_IOC_MAGIC, 30, int)
#define VEDRV_CMD_GET_CLOCK_GATING_STATE     _IOW(VE_IOC_MAGIC, 31, uint64_t)
#endif /*VE_DRV_H_INCLUDE_*/
