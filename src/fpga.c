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
 * @file fpga.c
 * @brief VE driver fpga specific functions.
 */

#include <linux/kernel.h>
#include "ve_drv.h"
#include "internal.h"

#define PCI_BAR2_MSTR_RST_OFFSET	(0x14000B0)
#define PCI_BAR2_PEU_CHKINH_OFFSET	(0x1484C00)
#define PCI_BAR2_XIU_HOT_RST_OFFSET	(0x1484000)
#define PCI_BAR2_DGU_PTCFG_OFFSET	(0x1400000)
#define PCI_BAR2_XIU_PTCFG_OFFSET	(0x1480000)
#define PCI_BAR2_DMU_PTCFG_OFFSET	(0x1490000)
#define PCI_BAR2_VPU_LESS_MODE_OFFSET	(0x1602098)
#define PCI_BAR2_DGUXIUDMU_PTCFG_OFFSET	(0x16E0000)
#define PCI_BAR2_CORE0_PTCFG_OFFSET	(0x1700000)
#define PCI_BAR2_CORE1_PTCFG_OFFSET	(0x1710000)
#define PCI_BAR2_GS_DIAG_OFFSET		(0x14000B8)
#define PCI_BAR2_XIU_BAR2_SYNC_OFFSET	(0x1484018)
#define PCI_BAR2_SPU_L2_RETRY_OFFSET	(0x1600190)
#define PCI_BAR2_ENABLE_INTR1_OFFSET	(0x14000E0)
#define PCI_BAR2_ENABLE_INTR2_OFFSET	(0x14000E8)
#define PCI_BAR2_ENABLE_INTR3_OFFSET	(0x1400260)
#define PCI_BAR2_ENABLE_INTR4_OFFSET	(0x1400238)
#define PCI_BAR2_CORE0_DGCP_OFFSET	(0x1460000)
#define PCI_BAR2_CORE0_SPU_OFFSET	(0x1500000)
#define PCI_BAR2_CORE0_AVP_OFFSET	(0x1502000)
#define PCI_BAR2_CORE1_DGCP_OFFSET	(0x1461000)
#define PCI_BAR2_CORE1_SPU_OFFSET	(0x1510000)
#define PCI_BAR2_CORE1_AVP_OFFSET	(0x1512000)

#define FPGA_INIT_MSTR_RST_DATA		(0xFFFF800080008080)
#define FPGA_INIT_PEU_CHKINH_DATA	(0x0028300000000000)
#define FPGA_INIT_XIU_HOT_RST_DATA	(0x0000000000008000)
#define FPGA_INIT_DGU_PTCFG_DATA	(0x0000000000FC0000)
#define FPGA_INIT_XIU_PTCFG_DATA	(0x0000000000800000)
#define FPGA_INIT_DMU_PTCFG_DATA	(0x0000000000FC0000)
#define FPGA_INIT_DMU_PTCFG_CONFIRM	(0x0000000000F80000)
#define FPGA_INIT_VPU_LESS_MODE_DATA	(0x0000000000000001)
#define FPGA_INIT_VPU_LESS_MODE_DATA_105	(0x0000000000000002)
#define FPGA_INIT_DGUXIUDMU_PTCFG_DATA	(0x0000000004FC0000)
#define FPGA_INIT_DGUXIUDMU_PTCFG_EC_DATA	(0x4000000004FC0000)
#define FPGA_INIT_CORE0_PTCFG_DATA	(0x0000000000FC0000)
#define FPGA_INIT_CORE0_PTCFG_EC_DATA	(0x8000000000FC0000)
#define FPGA_INIT_CORE1_PTCFG_DATA	FPGA_INIT_CORE0_PTCFG_DATA
#define FPGA_INIT_CORE1_PTCFG_EC_DATA	FPGA_INIT_CORE0_PTCFG_EC_DATA
#define FPGA_INIT_GS_DIAG_DATA		(0x0000000000000000)
#define FPGA_INIT_GS_DIAG_EC_DATA	(0xFFFF80008000F080)
#define FPGA_INIT_XIU_BAR2_SYNC_DATA	(0x0000800100000000)
#define FPGA_INIT_PU_L2_RETRY_DATA	(0x03fc000000000000)
#define FPGA_INIT_ENABLE_INTR1_DATA	(0xFFFF000000000080)
#define FPGA_INIT_ENABLE_INTR2_DATA	(0xFFFFFFFF00000000)
#define FPGA_INIT_ENABLE_INTR2_DATA_105	(0xFFFFFFFF00800000)
#define FPGA_INIT_ENABLE_INTR3_DATA	(0x0011200000000000)
#define FPGA_INIT_ENABLE_INTR4_DATA	(0x8000000000000000)

/* simulated error */
#define PCI_BAR2_SIM_ERR_80_CO_OFFSET	(0x1400020)	/* Check ON */
#define PCI_BAR2_SIM_ERR_80_AS_OFFSET	(0x14000c8)	/* Assert error (HMC) */
#define PCI_BAR2_SIM_ERR_81_CO_OFFSET	(0x14200b8)	/* Check ON */
#define PCI_BAR2_SIM_ERR_81_AS_OFFSET	(0x14000c8)	/* Assert error(DIAG) */
#define SIM_ERR_80_CO_DATA	(0x4000000000000000)
#define SIM_ERR_80_AS_DATA	(0x0800000000000000)
#define SIM_ERR_81_CO_DATA	(0x0000000000001000)
#define SIM_ERR_81_AS_DATA	(0x0200000000000000)

/**
 * @brief Check FPGA initialization
 *
 * @param[in] dev: VE device structure
 *
 * @return 0 on success. -1 on failure.
 */
static int ve_check_fpga_status(struct ve_dev *dev)
{
	struct pci_dev *pdev = dev->pdev;
	struct ve_hw_info *info = &dev->node->hw_info;
	uint64_t data;

	switch (info->model) {
	case FPGA_MODEL_106:
	case FPGA_MODEL_107:
		ve_bar2_read64(dev, 0x001487000, &data);
		pdev_info(pdev, "0x001487000: %016llx\n", data);
		goto bar0_check;
	default:
		break;
	}
	/* DGU GS CHKON read */
	ve_bar2_read64(dev, PCI_BAR2_GS_DIAG_OFFSET, &data);
	if (data != FPGA_INIT_GS_DIAG_EC_DATA) {
		pdev_err(pdev, "DGU GS CHKON is not initialized(%llx)\n", data);
		goto not_initialized;
	}

	/* DGU GS read */
	ve_bar2_read64(dev, PCI_BAR2_DGU_PTCFG_OFFSET, &data);
	if (data != FPGA_INIT_DGUXIUDMU_PTCFG_EC_DATA) {
		pdev_err(pdev, "DGU GS is not initialized(%llx)\n", data);
		goto not_initialized;
	}

	/* XIU GS read */
	ve_bar2_read64(dev, PCI_BAR2_XIU_PTCFG_OFFSET, &data);
	if (data != FPGA_INIT_DGUXIUDMU_PTCFG_EC_DATA) {
		pdev_err(pdev, "XIU GS is not initialized(%llx)\n", data);
		goto not_initialized;
	}

	/* DMU GS read */
	ve_bar2_read64(dev, PCI_BAR2_DMU_PTCFG_OFFSET, &data);
	if (data != FPGA_INIT_DGUXIUDMU_PTCFG_EC_DATA) {
		pdev_err(pdev, "DMU GS is not initialized(%llx)\n", data);
		goto not_initialized;
	}

	/* CORE0 */
	if (!(info->core_enables & (1 << 0)))
		goto bar0_check;

	/* CORE0 DGCP GS read */
	ve_bar2_read64(dev, PCI_BAR2_CORE0_DGCP_OFFSET, &data);
	if (data != FPGA_INIT_CORE0_PTCFG_EC_DATA) {
		pdev_err(pdev, "CORE0 DGCP GS is not initialized(%llx)\n",
				data);
		goto not_initialized;
	}

	/* CORE0 SPU GS read */
	ve_bar2_read64(dev, PCI_BAR2_CORE0_SPU_OFFSET, &data);
	if (data != FPGA_INIT_CORE0_PTCFG_EC_DATA) {
		pdev_err(pdev, "CORE0 SPU GS is not initialized(%llx)\n", data);
		goto not_initialized;
	}

	/* CORE0 AVP GS read */
	ve_bar2_read64(dev, PCI_BAR2_CORE0_AVP_OFFSET, &data);
	if (data != FPGA_INIT_CORE0_PTCFG_EC_DATA) {
		pdev_err(pdev, "CORE0 AVP GS is not initialized(%llx)\n", data);
		goto not_initialized;
	}

	/* CORE1 */
	if (!(info->core_enables & (1 << 1)))
		goto bar0_check;

	/* CORE1 DGCP GS read */
	ve_bar2_read64(dev, PCI_BAR2_CORE1_DGCP_OFFSET, &data);
	if (data != FPGA_INIT_CORE1_PTCFG_EC_DATA) {
		pdev_err(pdev, "CORE0 DGCP GS is not initialized(%llx)\n",
				data);
		goto not_initialized;
	}

	/* CORE1 SPU GS read */
	ve_bar2_read64(dev, PCI_BAR2_CORE1_SPU_OFFSET, &data);
	if (data != FPGA_INIT_CORE1_PTCFG_EC_DATA) {
		pdev_err(pdev, "CORE1 SPU GS is not initialized(%llx)\n", data);
		goto not_initialized;
	}

	/* CORE1 AVP GS read */
	ve_bar2_read64(dev, PCI_BAR2_CORE1_AVP_OFFSET, &data);
	if (data != FPGA_INIT_CORE1_PTCFG_EC_DATA) {
		pdev_err(pdev, "CORE1 AVP GS is not initialized(%llx)\n", data);
		goto not_initialized;
	}

 bar0_check:
	/* Reset PCIATB entry 0 */
	ve_bar2_write64_20(dev, PCI_BAR2_SCR_OFFSET + CREG_PCIATB_OFFSET, 0);
	ve_bar2_read64_sync(dev, PCI_BAR2_SCR_OFFSET + CREG_PCIATB_OFFSET,
			&data);
	pdev_dbg(pdev, "PCIATB0 = %llx\n", data);

	/* BAR0 check */
	ve_mmio_write64(dev->bar[0], 0xDEADBEEFDEADBEEF);
	ve_mmio_read64(dev->bar[0], &data);
	if (data != 0xDEADBEEFDEADBEEF) {
		pdev_err(pdev, "BAR0 is not initialized(%llx)\n", data);
		goto not_initialized;
	}
	ve_mmio_write64(dev->bar[0], 0);

	pdev_info(pdev, "VE-FPGA is initialized\n");

	return 0;
 not_initialized:
	return -1;
}

/**
 * @brief initializes VE-FPGA device.
 *        As for ASIC version, this routine is done by Hardware.
 *
 * @param[in] dev: VE device structure
 *
 * @return: 0 on success. negative on failure.
 */
int ve_init_fpga(struct ve_dev *dev)
{
	struct ve_hw_info *info = &dev->node->hw_info;
	int err = 0;

	pdev_dbg(dev->pdev, "Initializing VE-FPGA..\n");

	/* initialize MSTR_RST */
	ve_bar2_write64_delay(dev, PCI_BAR2_MSTR_RST_OFFSET,
			FPGA_INIT_MSTR_RST_DATA, 100);
	ve_bar2_write64_delay(dev, PCI_BAR2_MSTR_RST_OFFSET, 0,
			100);

	switch (info->model) {
	case FPGA_MODEL_105:
		/* PEU CHKINH (Bug workaround) */
		ve_bar2_write64_delay(dev, PCI_BAR2_PEU_CHKINH_OFFSET,
				FPGA_INIT_PEU_CHKINH_DATA, 100);
		/* Inhibit EIF on XIU Hot Reset (Bug workaround) */
		ve_bar2_write64_delay(dev, PCI_BAR2_XIU_HOT_RST_OFFSET,
				FPGA_INIT_XIU_HOT_RST_DATA, 100);
		break;
	case FPGA_MODEL_106:
	case FPGA_MODEL_107:
		/* PEU CHKINH */
		ve_bar2_write64_delay(dev, 0x01484C00, 0x00A9700000000000, 100);

		/* PEU EIF RESET */
		ve_bar2_write64_delay(dev, 0x01480020, 0x0040000000000000, 100);

		/* PEU EIF RESET cancel */
		ve_bar2_write64_delay(dev, 0x01480040, 0x0040000000000000, 100);

		/* PEU cancel CHKINH */
		ve_bar2_write64_delay(dev, 0x01484C00, 0x0029700000000000, 100);
		/* Inhibit EIF on XIU Hot Reset (Bug workaround) */
		ve_bar2_write64_delay(dev, PCI_BAR2_XIU_HOT_RST_OFFSET,
				FPGA_INIT_XIU_HOT_RST_DATA, 100);
	default:
		break;
	}
	/* initialize DGU/XIU/DMU PTCFG */
	ve_bar2_write64_delay(dev, PCI_BAR2_DGUXIUDMU_PTCFG_OFFSET,
			FPGA_INIT_DGUXIUDMU_PTCFG_EC_DATA, 100);

	/* initialize CORE0 */
	if (info->core_enables & (1 << 0)) {
		pdev_dbg(dev->pdev, "Initializing FPGA core 0\n");
		ve_bar2_write64_delay(dev, PCI_BAR2_CORE0_PTCFG_OFFSET,
				FPGA_INIT_CORE0_PTCFG_EC_DATA, 100);
	}

	/* initialize CORE1 */
	if (info->core_enables & (1 << 1)) {
		pdev_dbg(dev->pdev, "Initializing FPGA core 1\n");
		ve_bar2_write64_delay(dev, PCI_BAR2_CORE1_PTCFG_OFFSET,
				FPGA_INIT_CORE1_PTCFG_EC_DATA, 100);
	}

	switch (info->model) {
	case FPGA_MODEL_106:
	case FPGA_MODEL_107:
		/* haikiyokushi */
		ve_bar2_write64_delay(dev, 0x016e0020, 0x0000000004000000, 100);
		ve_bar2_write64_delay(dev, 0x01700020, 0x0000000004000000, 100);
		ve_bar2_write64_delay(dev, 0x01483000, 0xffffffffffffffff, 100);
		/* GS CHKON */
		ve_bar2_write64_delay(dev, PCI_BAR2_GS_DIAG_OFFSET,
				0xFFC080008000F080, 100);
		break;
	default:
		/* initialize GS(DIAG) */
		ve_bar2_write64_delay(dev, PCI_BAR2_GS_DIAG_OFFSET,
				FPGA_INIT_GS_DIAG_EC_DATA, 100);
		break;
	}

	switch (info->model) {
	case FPGA_MODEL_105:
	case FPGA_MODEL_106:
	case FPGA_MODEL_107:
		/* Change delay of XIU BAR2 SYNC time */
		ve_bar2_write64_delay(dev, PCI_BAR2_XIU_BAR2_SYNC_OFFSET,
				FPGA_INIT_XIU_BAR2_SYNC_DATA, 100);
		/**
		 * Enable SPU L2$ retly functionality
		 * (EIF on retrying 255 times)
		 */
		ve_bar2_write64_delay(dev, PCI_BAR2_SPU_L2_RETRY_OFFSET,
				FPGA_INIT_PU_L2_RETRY_DATA, 100);
		break;
	default:
		break;
	}

	switch (info->model) {
	case FPGA_MODEL_106:
	case FPGA_MODEL_107:
		/* ALL DGCP CORE HWCG ON */
		ve_bar2_write64_delay(dev, 0x01660020, 0x0000000000000800, 100);
		/* ALL DGCP NRT config OFF */
		ve_bar2_write64_delay(dev, 0x01660040, 0x0000000000800000, 100);
		/* ALL DGLM MCU config OFF */
		ve_bar2_write64_delay(dev, 0x01670040, 0x0000000000400000, 100);
		break;
	default:
		break;
	}

	/* AXI Slave ID = 2 */
	ve_bar2_write64_delay(dev, 0x01490720, 0xc000000000000000, 100);
	ve_bar2_write64_delay(dev, 0x01490728, 0xc000000000000000, 100);
	ve_bar2_write64_delay(dev, 0x01492c28, 0x8081000202020100, 100);

	/* VPU Mode */
	switch (info->model) {
	case FPGA_MODEL_105:
		ve_bar2_write64_delay(dev, PCI_BAR2_VPU_LESS_MODE_OFFSET,
				FPGA_INIT_VPU_LESS_MODE_DATA_105, 100);
		break;
	case FPGA_MODEL_106:
	case FPGA_MODEL_107:
		/* type 0x42 and 0x62 has VPU */
		if (info->type == 0x42 || info->type == 0x62) {
			ve_bar2_write64_delay(dev, 0x01602110,
					0x0004000000000000, 100);
			ve_bar2_write64_delay(dev, 0x01602118,
					0x0600000000000000, 100);
		} else {
			ve_bar2_write64_delay(dev,
					PCI_BAR2_VPU_LESS_MODE_OFFSET,
					FPGA_INIT_VPU_LESS_MODE_DATA_105, 100);
		}
		break;
	default:
		ve_bar2_write64_delay(dev, PCI_BAR2_VPU_LESS_MODE_OFFSET,
				FPGA_INIT_VPU_LESS_MODE_DATA, 100);
		break;
	}

	/* Enable interrupt */
	switch (info->model) {
	case FPGA_MODEL_104:
		ve_bar2_write64_delay(dev, PCI_BAR2_ENABLE_INTR1_OFFSET,
			FPGA_INIT_ENABLE_INTR1_DATA, 100);
		ve_bar2_write64_delay(dev, PCI_BAR2_ENABLE_INTR2_OFFSET,
			FPGA_INIT_ENABLE_INTR2_DATA, 100);
		break;
	case FPGA_MODEL_105:
		ve_bar2_write64_delay(dev, PCI_BAR2_ENABLE_INTR1_OFFSET,
			FPGA_INIT_ENABLE_INTR1_DATA, 100);
		ve_bar2_write64_delay(dev, PCI_BAR2_ENABLE_INTR2_OFFSET,
			FPGA_INIT_ENABLE_INTR2_DATA_105, 100);
		break;
	case FPGA_MODEL_106:
	case FPGA_MODEL_107:
		ve_bar2_write64_delay(dev, PCI_BAR2_ENABLE_INTR1_OFFSET,
			0xFFC0000000000080, 100);
		ve_bar2_write64_delay(dev, PCI_BAR2_ENABLE_INTR2_OFFSET,
			0xFFC0EF9800800000, 100);
	default:
		break;
	}
	ve_bar2_write64_delay(dev, PCI_BAR2_ENABLE_INTR3_OFFSET,
			FPGA_INIT_ENABLE_INTR3_DATA, 100);
	/* Report exception mode */
	switch (info->model) {
	case FPGA_MODEL_105:
	case FPGA_MODEL_106:
	case FPGA_MODEL_107:
		ve_bar2_write64_delay(dev, PCI_BAR2_ENABLE_INTR4_OFFSET,
				FPGA_INIT_ENABLE_INTR4_DATA, 100);
		break;
	default:
		break;
	}

	/* EIF CHKINH config (bug workaround) */
	if (info->model == FPGA_MODEL_104)
		ve_bar2_write64_delay(dev, 0x01484C00, 0x0000004000000000, 100);

	ve_bar2_write64_delay(dev, 0x01500208, 0x0900000000000000, 100);

	err = ve_check_fpga_status(dev);

	return err;
}

