/*
 * Vector Engine Driver
 *
 * Copyright (C) 2017-2018 NEC Corporation
 * This file is part of VE Driver.
 *
 * VE Driver is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * VE Driver is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with the VE Driver; if not, see
 * <http://www.gnu.org/licenses/>.
 */

/*
 * @file mmap_ve3.c
 * @brief VE3 specific functions for mmap
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/kthread.h>

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/file.h>

#include <linux/pci.h>
#include <linux/interrupt.h>

#include <linux/mm.h>

#include <linux/uaccess.h>
#define _VE_ARCH_VE3_ (1)
#include "ve_drv.h"
#include "internal.h"
#include "mmio.h"

static int ve3_is_cr_area(uint64_t bar_offset, uint64_t size)
{
	uint64_t tail = bar_offset + size - 1;
	return VEDRV_VE3_PCI_BAR4_SCR_OFFSET + CREG_CR_SET_OFFSET(0) <= bar_offset && 
		bar_offset < VEDRV_VE3_PCI_BAR4_SCR_OFFSET+ CREG_CR_SET_OFFSET(0) + CREG_CR_AREA_SIZE &&
		VEDRV_VE3_PCI_BAR4_SCR_OFFSET + CREG_CR_SET_OFFSET(0) <= tail &&
		tail < VEDRV_VE3_PCI_BAR4_SCR_OFFSET + CREG_CR_SET_OFFSET(0) + CREG_CR_AREA_SIZE;
}

/**
 * @brief Calculate phisical offset address of mmap
 *
 * @param[in] vedev: VE device structure
 * @param head: head of mapping address
 * @param size: mapping size
 * @param[out] bar: BAR number will be stored
 *
 * @return offset from each BAR.
 */
int ve_drv_ve3_map_range_offset(const struct ve_dev *vedev, off_t head,
			       size_t size, int *bar, unsigned long *offset)
{
	long tail = head + size - 1;

	pdev_dbg(vedev->pdev, "head = %lx, tail = %lx\n", head, tail);

	if (head >= VEDRV_VE3_MAP_BAR0_OFFSET &&
	    head < VEDRV_VE3_MAP_BAR0_OFFSET + vedev->bar_size[0] &&
	    tail >= VEDRV_VE3_MAP_BAR0_OFFSET &&
	    tail < VEDRV_VE3_MAP_BAR0_OFFSET + vedev->bar_size[0]) {
		/* mapping range is in BAR0 */
		*bar = 0;
		*offset = head - VEDRV_VE3_MAP_BAR0_OFFSET;
		/* check on fault */
		return 0;
	} else if (head >= VEDRV_VE3_MAP_BAR2_OFFSET &&
		   head < VEDRV_VE3_MAP_BAR2_OFFSET + vedev->bar_size[2] &&
		   tail >= VEDRV_VE3_MAP_BAR2_OFFSET &&
		   tail < VEDRV_VE3_MAP_BAR2_OFFSET + vedev->bar_size[2]) {
		/* mapping range is in BAR2 */
		*bar = 2;
		*offset = head - VEDRV_VE3_MAP_BAR2_OFFSET;
		/* Only sysadmin may map registers area */
		if (capable(CAP_SYS_ADMIN))
			return 0;
		else
			return -EACCES;
	} else if (head >= VEDRV_VE3_MAP_BAR4_OFFSET &&
		   head < VEDRV_VE3_MAP_BAR4_OFFSET + vedev->bar_size[4] &&
		   tail >= VEDRV_VE3_MAP_BAR4_OFFSET &&
		   tail < VEDRV_VE3_MAP_BAR4_OFFSET + vedev->bar_size[4]) {
		/* mapping range is in BAR4 */
		*bar = 4;
		*offset = head - VEDRV_VE3_MAP_BAR4_OFFSET;
		if (ve3_is_cr_area(*offset, size)) {
			/* check on access if the position is in CR area */
			return 0;
		} else {
			/* Only sysadmin may map registers area */
			if (capable(CAP_SYS_ADMIN))
				return 0;
			else
				return -EACCES;
		}
		return 0;
	}

	return -EINVAL;
}

/**
 * @brief Return if mapping of this page is permitted or not
 *
 * @param[in] vedev: VE device structure
 * @param bar: BAR number (0, 2, 4)
 * @param bar_offset: offset from top of BAR.
 *
 * @return 0 if mapping is permitted.
 *         Negative if mapping is not permitted.
 */
int ve_drv_ve3_permit_to_map(const struct ve_dev *vedev, int bar,
				unsigned long bar_offset)
{
	off_t aligned_offset;
	int entry;

	pdev_trace(vedev->pdev);

	/*
	 * ADMIN is always allowed to map any area.
	 * BAR2 and BAR4 except CR area check was already done.
	 */
	if (capable(CAP_SYS_ADMIN) || bar == 2 ||
		(bar == 4 && !ve3_is_cr_area(bar_offset, PAGE_SIZE)))
		return 0;

	if (bar == 0) {
		uint64_t pciatba;
		uint32_t pciatb_pagesize;
		/* Refresh PCIATB pagesize */
		ve_bar2_read64(vedev, VEDRV_VE3_PCI_BAR2_SCR_OFFSET
				+ CREG_PCIATBA_OFFSET, &pciatba);
		if (pciatba & 1)
			pciatb_pagesize = PCIATB_64M_PAGE;
		else
			pciatb_pagesize = PCIATB_2M_PAGE;

		/* calc PCIATB pagesize aligned address */
		aligned_offset = bar_offset
			- (bar_offset % (pciatb_pagesize));

		/* calc PCIATB entry number */
		entry = aligned_offset / (pciatb_pagesize);

		pdev_dbg(vedev->pdev, "VE memory mapping, pagesize = %x\n",
				pciatb_pagesize);
		pdev_dbg(vedev->pdev,
		"bar_offset = %lx, aligned_offset = %lx, PCIATB entry = %d\n",
				bar_offset, aligned_offset, entry);

		return ve_drv_check_pciatb_entry_permit(vedev, entry);

	} else if (bar == 4 && ve3_is_cr_area(bar_offset, PAGE_SIZE)) {
		/* calc 8k aligned address */
		aligned_offset = bar_offset - (bar_offset % (2 * 4096));
		aligned_offset -= (VEDRV_VE3_PCI_BAR4_SCR_OFFSET + CREG_CR_SET_OFFSET(0));
		/* calc CR page number */
		entry = aligned_offset / 2 / 4096;

		pdev_dbg(vedev->pdev, "CR mapping\n");

		pdev_dbg(vedev->pdev,
		"bar_offset = %lx, aligned_offset = %lx, page num = %d\n",
				bar_offset, aligned_offset, entry);

		return ve_drv_check_cr_entry_permit(vedev, entry);
	}

	return -1;
}
