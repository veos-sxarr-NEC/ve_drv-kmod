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
/**
 * @file ve_config_regs.c
 * @brief Read VE config registers in config space
 */

#include <linux/pci.h>
#include "internal.h"

/**
 * @brief Read VE Config Registers in config space
 *
 * @param[in] vedev: VE device structure
 * @param num: the number of words; read num x 4 bytes.
 * @param[out] data: buffer to read data
 */
int ve_drv_read_ve_config_regs(const struct ve_dev *vedev, size_t num,
				u32 *data)
{
	struct pci_dev *dev = vedev->pdev;
	int i;
	int addr;
	addr = PCI_CONFIG_VE_CONFIG_REGS_OFFSET;
	for (i = 0; i < num; ++i) {
		int ret = pci_read_config_dword(dev, addr, &data[i]);
		if (ret < 0) {
			pdev_err(vedev->pdev,
				"Failed to read PCI config (addr = 0x%x)\n",
				addr);
			return -1;
		}
		addr += sizeof(u32);
	}
	return 0;
}

void ve_drv_set_model_type(struct ve_model_type *info, u32 data)
{
	info->model = (uint8_t)((data & 0xff000000) >> 24);
	info->type = (uint8_t)((data & 0x00ff0000) >> 16);
	info->cpu_version = (uint8_t)((data & 0x0000ff00) >> 8);
	info->version = (uint8_t)(data & 0x000000ff);
}

/**
 * @brief Fill VE device information in ve_dev
 *
 * Read VE Configuration and fill VE device information in VE device structure.
 *
 * @param vedev: VE device structure
 */
int ve_drv_read_model_type(const struct ve_dev *vedev,
			struct ve_model_type *info)
{
	struct pci_dev *pdev = vedev->pdev;
	u32 data;
	int ret;
	pdev_trace(pdev);
	ret = ve_drv_read_ve_config_regs(vedev, 1, &data);
	if (ret)
		return -1;

	ve_drv_set_model_type(info, data);

	pdev_dbg(pdev, "model = 0x%x\n", info->model);
	pdev_dbg(pdev, "type = 0x%x\n", info->type);
	pdev_dbg(pdev, "cpu_version = 0x%x\n", info->cpu_version);
	pdev_dbg(pdev, "version = 0x%x\n", info->version);

	return 0;
}
