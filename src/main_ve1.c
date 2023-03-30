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
 * @file main_ve1.c
 * @brief VE1 and VE2 specific part of VE driver main file
 */

#define _VE_ARCH_VE1_ (1)
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/aer.h>
#include "ve_drv.h"
#include "hw.h"
#include "internal.h"
#include "mmio.h"

/* Skip FW update in probe */
static int skip_fw_update;
module_param(skip_fw_update, int, 0600);
MODULE_PARM_DESC(skip_fw_update,
	"If this parameter is not zero, driver will skip FW Update in probe.");

static int ve1_fill_hw_info(struct ve_dev *vedev)
{
	u32 data[VE1_VCR_SIZE];
	struct ve_node *node = vedev->node;
	struct ve_hw_info *info = &node->hw_info;

	int ret;
	ret = ve_drv_read_ve_config_regs(vedev, VE1_VCR_SIZE, data);
	if (ret != 0)
		return -EIO;
	ve_drv_set_model_type(&info->model_type, data[0]);

	info->num_of_core = (uint8_t)((data[1] & 0xff000000) >> 24);
	info->core_enables = data[1] & 0x00ffffff;

	info->vmcfw_version = (uint16_t)(data[10] & 0x0000ffff);
	info->memory_size = (uint16_t)((data[11] & 0xffff0000) >> 16);
	info->memory_clock = (uint16_t)(data[11] & 0x0000ffff);
	info->core_clock = (uint16_t)((data[12] & 0xffff0000) >> 16);
	info->base_clock = (uint16_t)(data[12] & 0x0000ffff);

	info->chip_sn[0] = (uint64_t)data[2] << 32;
	info->chip_sn[0] |= (uint64_t)data[3];
	info->chip_sn[1] = (uint64_t)data[4] << 32;
	info->chip_sn[1] |= (uint64_t)data[5];

	info->board_sn[0] = (uint64_t)data[6] << 32;
	info->board_sn[0] |= (uint64_t)data[7];
	info->board_sn[1] = (uint64_t)data[8] << 32;
	info->board_sn[1] |= (uint64_t)data[9];

	return 0;
}

static void ve1_fill_model_info(const struct ve_dev *vedev, \
			struct ve_model_info *model)
{
	model->num_of_crpage = VE1_CR_PAGE;
	model->num_of_pciatb = VE1_PCIATB_ENTRY;
	model->i_cache_size = 32; /* 32 KiB */
	model->d_cache_size = 32; /* 32 KiB */
	model->l2_cache_size = 256; /* 256 KiB */
	model->llc_cache_size = 16 * 1024; /* 16 MiB */
}

static int ve1_init_node(struct ve_dev *vedev, struct ve_node *node)
{
	struct ve1_archdep_data *data = node->ve_archdep_data;
	/* initialize intvec */
	data->cond.ve_wait_irq_type = VEDRV_IRQ_TYPE_VE1;
	data->cond.upper = 0;
	data->cond.lower = 0;
	node->cond = (struct ve_wait_irq *)&data->cond;
	/* set ve_state */
	node->ve_state = VE_ST_UNINITIALIZED;
	/* arch_hw_info has been filled here; was set on ve1_fill_hw_info(). */
	return 0;
}

static void ve1_fini_node(struct ve_dev *vedev, struct ve_node *node)
{
	kfree(node->cond);
	node->cond = 0;
}

/**
 * @brief Check if the PCI device needs firmware update
 *
 * @param[in] pdev: PCI device structure
 *
 * @return true if it needs update. false if it doesn't.
 */
static int ve1_device_needs_firm_update(struct ve_dev *vedev)
{
	struct pci_dev *pdev = vedev->pdev;
	struct pci_dev *parent = pdev->bus->self;
	struct ve_hw_info *info = &vedev->node->hw_info;
	u16 link_sta;

	pdev_trace(pdev);

	pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_sta);
	/* Skip FW update if it is already linked with Gen3 */
	if ((link_sta & PCI_EXP_LNKSTA_CLS_8_0GB) == PCI_EXP_LNKSTA_CLS_8_0GB) {
		pdev_dbg(pdev, "Device is already linked with Gen3\n");
		return false;
	}

	switch (info->model_type.model) {
	case MODEL_VE1:
	case MODEL_VE2:
		return 1;
	case QEMU_MODEL_0:
		return 0;
	default:
		pdev_warn(pdev, "Unsupported Device (model = 0x%x)\n",
				info->model_type.model);
		return 0;
	}
}

static int ve1_recover_from_chip_reset(struct ve_dev *vedev, u16 *aer_cap,
		int enable_irq, int fw_update, int sbr)
{
	int err;
	struct ve1_wait_irq *cond;

	pdev_trace(vedev->pdev);

	/* Restore PCI config and link retrain to link with Gen3 */

	err = ve_recover_from_link_down(vedev, aer_cap, fw_update, sbr);
	if (err)
		return err;

	/* Enable MSI-X */
	if (enable_irq) {
		cond = (struct ve1_wait_irq *)vedev->node->cond;
		/* clear all pending interrupt bits in driver */
		cond->lower = 0;
		cond->upper = 0;

		err = ve_drv_enable_irqs(vedev);
		if (err)
			return err;
	}

	return 0;
}

static inline void do_link_down_eif_inh(struct ve_dev *vedev)
{
	pdev_trace(vedev->pdev);

	ve_bar2_write64(vedev, LINK_DOWN_EIF_INH_OFFSET,
			LINK_DOWN_EIF_INH_DATA);
}


static inline void do_ve1_chip_reset(struct ve_dev *vedev)
{
	pdev_info(vedev->pdev, "Reset VE chip\n");

	/* Cancel Interrupt settings */
	ve_bar2_write64(vedev, 0x01420090, 0xffc0fffff0008080);
	ve_bar2_write64(vedev, 0x014200A8, 0xffc0ef9800000000);

	/* VE Card reset */
	ve_bar2_write64(vedev, 0x01400198, 0x0000020000000200);
	ve_bar2_write64(vedev, 0x01400190, 0x8800000000200052);
}

static inline void do_ve_secondary_bus_reset(struct ve_dev *vedev)
{
	struct pci_dev *parent = vedev->pdev->bus->self;

	pdev_info(parent, "Reset Secondary Bus\n");

	/* Link down EIF INH */
	do_link_down_eif_inh(vedev);

	/* Issue secondary bus reset */
#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
	pci_reset_bridge_secondary_bus(parent);
#else
	pci_bridge_secondary_bus_reset(parent);
#endif
}

static int ve1_reset_and_fwupdate(struct ve_dev *vedev, uint64_t sbr,
		int update_only, int irq)
{
	struct pci_dev *pdev = vedev->pdev;
	int err;
	u16 aer_cap;
	int retry=0;
	pdev_trace(vedev->pdev);

	err = ve_prepare_for_chip_reset(vedev, &aer_cap, irq, sbr);
	if (err)
		return err;

	if (update_only)
		goto load_fw;

	/*
	 * Do secondary bus reset or chip reset.
	 */
	if (sbr)
		do_ve_secondary_bus_reset(vedev);
	else
		do_ve1_chip_reset(vedev);


        /* Wait wait_after_vereset_sec sec */
        do {
                ssleep(1);
                err = ve_check_pci_link(vedev->pdev);
        } while( ++retry < wait_after_vereset_sec && err );

        if(err){
                pdev_err(pdev, "Waited for %d seconds, but VE RESET failed\n", retry);
	}

	/* Skip FW loading */
	goto recover_chip_reset;

 load_fw:
	err = ve1_device_needs_firm_update(vedev);
	if (err == false)
		goto recover_chip_reset;

	/*
	 * Load PCIe Gen3 firmware here. And then chip will be reset.
	 * We need to wait for a while for the PCIe link comes up.
	 */
	pdev_info(pdev, "Loading PCIe Firmware\n");

	err = ve_drv_ve1_load_gen3_firmware(vedev);
	if (err) {
		pdev_err(pdev, "Failed to load PCIe Firmware\n");
		(void)ve1_recover_from_chip_reset(vedev, &aer_cap, irq,
				update_only, 0);
		return err;
	}

 recover_chip_reset:
	err = ve1_recover_from_chip_reset(vedev, &aer_cap, irq, update_only,
			sbr);

	return err;
}

int ve_drv_ve1_chip_reset_sbr(struct ve_dev *vedev, uint64_t sbr)
{
	int irq = 1;
	int err = 0;

	mutex_lock(&vedev->node->sysfs_mutex);
	if (vedev->node->os_state != OS_ST_OFFLINE) {
		err = -EAGAIN;
		goto err_state;
	}
	if (sbr > 1){
		err = -EINVAL;
		goto err_state;
	}
	if (sbr)
		irq = 0;
	err = ve1_reset_and_fwupdate(vedev, sbr, 0, irq);

 err_state:
	mutex_unlock(&vedev->node->sysfs_mutex);
	return err;
}

int ve_drv_ve1_firmware_update(struct ve_dev *vedev)
{
	int err = 0;

	mutex_lock(&vedev->node->sysfs_mutex);
	if (vedev->node->os_state != OS_ST_OFFLINE) {
		err = -EAGAIN;
		goto err_state;
	}
	err = ve1_reset_and_fwupdate(vedev, 0, 1, 1);

 err_state:
	mutex_unlock(&vedev->node->sysfs_mutex);
	return err;
}

static int ve1_init_fwupdate(struct ve_dev *vedev)
{
	if (!skip_fw_update) {
		int err;
		err = ve1_reset_and_fwupdate(vedev, 0, 1, 0);
		if (err && err != -EIO)
			return err;
	}
	return 0;
}

static inline void ve1_clear_intvec(struct ve_dev *vedev)
{
	/* Clear interrupt mask register */
	ve_bar2_write64_20(vedev,
		VEDRV_VE1_PCI_BAR2_SCR_OFFSET + CREG_INTERRUPT_VECTOR, ~0UL);
}

static int ve1_init_post_core(struct ve_dev *vedev)
{
	ve1_clear_intvec(vedev);
	return 0;
}

static void *ve1_exsrar_addr(const struct ve_dev *vedev, int core_id)
{
	uint64_t exsrar_offset = (VEDRV_VE1_PCI_BAR2_CREG_SIZE * core_id) +
			VEDRV_VE1_PCI_BAR2_SREG_OFFSET + SREG_EXSRAR_OFFSET;
	return (char *)vedev->bar[2] + exsrar_offset;
}

/**
 * @brief Read EXS register value from MMIO space
 *
 * @param[in] vedev: VE device structure
 * @param core_id: VE core ID
 *
 * @return EXS value
 */
static uint64_t ve1_get_exs(struct ve_dev *vedev, int core_id)
{
	uint64_t exs;
	ve_bar2_read64(vedev, VEDRV_VE1_PCI_BAR2_CREG_SIZE * core_id
			+ UREG_EXS_OFFSET, &exs);
	return exs;
}

static void ve1_core_intr_cb(struct ve_dev *vedev, int core_id)
{
	ve_bar2_write64_20(vedev,
			VEDRV_VE1_PCI_BAR2_SCR_OFFSET + CREG_INTERRUPT_VECTOR,
			(uint64_t)0x8000000000000000 >> core_id);
}

static void ve1_node_intr_cb(struct ve_dev *vedev, int entry)
{
	uint64_t cond_bit;
	struct ve1_wait_irq *cond = (struct ve1_wait_irq *)vedev->node->cond;
	/* set condition bit */
	if (entry < 64) {
		cond_bit = 0x1UL << entry;
		cond->lower |= cond_bit;
	} else {
		entry -= 64;
		cond_bit = 0x1UL << entry;
		cond->upper |= cond_bit;;
	}
	pdev_dbg(vedev->pdev, "lower = 0x%016llx, upper = 0x%016llx\n",
		cond->lower, cond->upper);
}

static irqreturn_t ve1_intr(struct ve_dev *vedev, int entry)
{
	if (unlikely(entry < 0 || 95 < entry))
		return IRQ_HANDLED;

	if (unlikely(entry > 63))
		/* Hw error */
		pdev_err(vedev->pdev, "Hw Error occurred (Entry = %d)\n",
				entry);

	if (entry < 16 && likely(!hw_intr_test_param))
		/* core interrupt: core# == entry */
		return ve_drv_generic_core_intr(vedev, entry, ve1_core_intr_cb);

	return ve_drv_generic_node_intr(vedev, entry, ve1_node_intr_cb);
}

static void ve1_request_stop_all(struct ve_dev *vedev)
{
	struct ve_hw_info *info = &vedev->node->hw_info;
	int core_id;
	off_t offset;

	/* PDMA */
	offset = VEDRV_VE1_PCI_BAR2_SCR_OFFSET + CREG_DMACTLP_OFFSET;
	ve_bar2_write64(vedev, offset, DMACTL_DISABLE_PERMIT);

	/* cores and UDMA */
	for (core_id = 0; core_id < vedev->node->core_fls; core_id++) {
		if (!(info->core_enables & (1 << core_id)))
			continue;

		offset = VEDRV_VE1_PCI_BAR2_CREG_SIZE * core_id;
		/* User DMA (Host) */
		ve_bar2_write64(vedev, offset +
			VEDRV_VE1_PCI_BAR2_SREG_OFFSET + SREG_DMACTLH_OFFSET,
			DMACTL_DISABLE_PERMIT);

		/* User DMA (Device) */
		ve_bar2_write64(vedev, offset +
			VEDRV_VE1_PCI_BAR2_SREG_OFFSET + SREG_DMACTLE_OFFSET,
			DMACTL_DISABLE_PERMIT);

		/* core */
		ve_bar2_write64(vedev, offset +
			VEDRV_VE1_PCI_BAR2_UREG_OFFSET + UREG_EXS_OFFSET,
			EXS_STATE_STOP);
	}
}

static int ve1_check_stopped(struct ve_dev *vedev)
{
	struct ve_hw_info *info = &vedev->node->hw_info;
	int core_id;
	off_t offset;
	uint64_t regdata;

	/* PDMA */
	offset = VEDRV_VE1_PCI_BAR2_SCR_OFFSET + CREG_DMACTLP_OFFSET;
	ve_bar2_read64(vedev, offset, &regdata);
	if (!(regdata & DMACTL_HALT_MASK))
		return 0;

	/* core and user DMA */
	for (core_id = 0; core_id < vedev->node->core_fls; core_id++) {
		if (!(info->core_enables & (1 << core_id)))
			continue;

		offset = VEDRV_VE1_PCI_BAR2_CREG_SIZE * core_id;
		/* User DMA (Host) */
		ve_bar2_read64(vedev, offset +
			VEDRV_VE1_PCI_BAR2_SREG_OFFSET + SREG_DMACTLH_OFFSET,
			&regdata);
		if (!(regdata & DMACTL_HALT_MASK))
			return 0;

		/* User DMA (Device) */
		ve_bar2_read64(vedev, offset +
			VEDRV_VE1_PCI_BAR2_SREG_OFFSET + SREG_DMACTLE_OFFSET,
			&regdata);
		if (!(regdata & DMACTL_HALT_MASK))
			return 0;

		/* core */
		ve_bar2_read64(vedev, offset +
			VEDRV_VE1_PCI_BAR2_UREG_OFFSET + UREG_EXS_OFFSET,
			&regdata);
		if (regdata & EXS_STATE_RUN)
			return 0;
	}

	return 1;
}

static int ve1_ve_state_transition(struct ve_dev *vedev,
			unsigned long cur_state, unsigned long new_state)
{
	if (new_state == VE_ST_ONLINE)
		ve1_clear_intvec(vedev);
	return 0;
}

static const struct ve_arch_class vedrv_ve1_arch_class = {
	.name = VE_DRV_ARCH_NAME_VE1,
	.expected_bar_mask = 0x3d, /* BAR01, 2, 3, 4, and 5 */
	.max_core_num = VE1_MAX_CORE_NUM,
	.num_sensors = 38,
	.init_early = 0,
	.fini_late = 0,
	.init_hw_check = 0,
	.fill_hw_info = ve1_fill_hw_info,
	.fill_model_info = ve1_fill_model_info,
	.init_node = ve1_init_node,
	.fini_node = ve1_fini_node,
	.init_post_node = ve1_init_fwupdate,
	.init_post_core = ve1_init_post_core,

	.exsrar_addr = ve1_exsrar_addr,
	.get_exs = ve1_get_exs,
	.ve_arch_ioctl_check_permission = ve_drv_ve1_ioctl_check_permission,
	.ve_arch_ioctl = ve_drv_ve1_arch_ioctl,
	.ve_arch_intr = ve1_intr,
	.ve_irq_type = VEDRV_IRQ_TYPE_VE1,
	.ve_wait_irq_size = sizeof(struct ve1_wait_irq),
	.ve_arch_wait_intr = ve_drv_ve1_wait_intr,
	.core_intr_undelivered = ve_drv_ve1_core_intr_undelivered,
	.ve_arch_map_range_offset = ve_drv_ve1_map_range_offset,
	.permit_to_map = ve_drv_ve1_permit_to_map,
	.request_stop_all = ve1_request_stop_all,
	.check_stopped = ve1_check_stopped,

	.ve_state_transition = ve1_ve_state_transition,
	.ve_arch_release = NULL,
	.ve_arch_sysfs_attr_groups = ve_drv_ve1_attribute_groups,

	.ve_archdep_size = sizeof(struct ve1_archdep_data),
};

const struct ve_arch_class *ve_arch_probe_ve1(struct ve_dev *vedev)
{
	struct pci_dev *pdev = vedev->pdev;
	int ret;
	struct ve_model_type info;

	pdev_trace(pdev);
	if (PCI_VENDOR_ID_VE1 != pdev->vendor ||
		PCI_DEVICE_ID_VE1 != pdev->device)
		return NULL;

	ret = ve_drv_read_model_type(vedev, &info);
	if (ret)
		return NULL;

	/* check header version */
	if (info.version != 1) {
		return 0;
	}
	/* check model */
	switch (info.model) {
	case MODEL_VE1:
	case MODEL_VE2:
	case QEMU_MODEL_0:
		/* supported */
		break;
	default:
		return 0;
	}
	return &vedrv_ve1_arch_class;
}
