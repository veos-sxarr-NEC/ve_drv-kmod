/*
 * Vector Engine Driver
 *
 * Copyright (C) 2017-2020 NEC Corporation
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
 * @file mmio_ve3.h
 * @brief MMIO functions for VE3
 */
#ifndef VE_DRV_MMIO_H_INCLUDE_
# error "never use \"mmio_ve3.h\" directly; include \"mmio.h\" instead."
#endif

#include "hw_ve3.h"

#ifndef VE_DRV_MMIO_VE3_H_INCLUDE_
#define VE_DRV_MMIO_VE3_H_INCLUDE_
VE_MMIO_WRITE64_BAR(2)
VE_MMIO_WRITE64_BAR(4)
VE_MMIO_READ64_BAR(2)
VE_MMIO_READ64_BAR(4)

/**
 * @brief Sync and read 64bit value from BAR2 space
 *
 * @param[in] vedev: VE device structure
 * @param offset: Offset from top of BAR2
 * @param[out] val: Readed 64bit value will be stored
 */
static inline void ve_bar2_read64_sync(const struct ve_dev *vedev,
				off_t offset, uint64_t *val)
{
	/* Sync in VE before read */
	ve_bar4_write64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET +
			CREG_SYNC_OFFSET, 0);

	ve_bar2_read64(vedev, offset, val);
}

/**
 * @brief Sync and read 64bit value from BAR4 space
 *
 * @param[in] vedev: VE device structure
 * @param offset: Offset from top of BAR4
 * @param[out] val: Readed 64bit value will be stored
 */
static inline void ve_bar4_read64_sync(const struct ve_dev *vedev,
				off_t offset, uint64_t *val)
{
	/* Sync in VE before read */
	ve_bar4_write64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET +
			CREG_SYNC_OFFSET, 0);

	ve_bar4_read64(vedev, offset, val);
}
#endif
