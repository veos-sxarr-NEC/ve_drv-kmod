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
 * @file mmio.h
 * @brief Inline functions for MMIO
 */
/* Architecture-independent files SHALL NOT include mmio.h */
#ifndef VE_DRV_MMIO_H_INCLUDE_
#define VE_DRV_MMIO_H_INCLUDE_
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include "hw.h"
#include "ve_drv.h"

/**
 * @brief Write 64bit value to MMIO address
 *
 * @param[in] to: Target kernel virtual address
 * @param val: 64bit value to be stored
 */
static inline void ve_mmio_write64(void *to, uint64_t val)
{
	writeq(val, to);
	/* in case of other arch than x86 */
	wmb();
}

#define VE_MMIO_WRITE64_BAR(bar_) \
static inline void ve_bar##bar_##_write64(const struct ve_dev *vedev, \
				off_t offset, uint64_t val) \
{ \
	pdev_dbg(vedev->pdev, "write: bar%d offset=0x%016lx, val=%016lx\n", \
			bar_, (unsigned long)offset, (unsigned long)val); \
	ve_mmio_write64((char *)vedev->bar[bar_] + offset, val); \
}

/**
 * @brief Read 64bit value from MMIO address
 *
 * @param[in] from: Target kernel virtual address
 * @param[out] val: Readed 64bit value will be stored
 */
static inline void ve_mmio_read64(void *from, uint64_t *val)
{
	/* in case of other arch than x86 */
	rmb();
	*val = readq(from);
}

#define VE_MMIO_READ64_BAR(bar_) \
static inline void ve_bar##bar_##_read64(const struct ve_dev *vedev, \
				off_t offset, uint64_t *val) \
{ \
	ve_mmio_read64((char *)vedev->bar[bar_] + offset, val); \
}

#if defined(_VE_ARCH_VE3_)
#include "mmio_ve3.h"
#elif defined(_VE_ARCH_VE1_)
#include "mmio_ve1.h"
#endif

#endif
