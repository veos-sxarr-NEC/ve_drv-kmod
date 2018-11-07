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
 * @file main.c
 * @brief VE driver main file.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/aer.h>
#include <linux/idr.h>
#include <linux/dma-mapping.h>
#include <linux/vmalloc.h>
#include "../config.h"
#include "commitid.h"
#include "ve_drv.h"
#include "internal.h"

#define VE_MAX_DEVICES         (1U << MINORBITS)
#define VE_REMOVE_TIMEOUT_MSECS	40

/* static strings */
char ve_driver_name[] = "ve_drv";
static const char ve_driver_string[] = "NEC Vector Engine Driver";
static const char ve_copyright[] = "Copyright (c) 2017-2018 NEC Corporation.";
static int ve_major;
static DEFINE_IDR(ve_idr);
/* Protect idr accesses */
static DEFINE_MUTEX(minor_lock);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NEC Corporation");
MODULE_DESCRIPTION("NEC Vector Engine Driver");
MODULE_VERSION(VERSION);
MODULE_INFO(release, RELEASE);
MODULE_INFO(gitcom, COMMITID);

/* for pci_driver */
static int ve_pci_probe(struct pci_dev *dev, const struct pci_device_id *id);
static void ve_pci_remove(struct pci_dev *dev);

/**
 * @brief PCI Device ID table
 */
static const struct pci_device_id ve_device_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_VE, PCI_DEVICE_ID_VE)},
	{0,},
};

/**
 * @brief PCI Driver table
 */
static struct pci_driver ve_drv_pci_driver = {
	.name = ve_driver_name,
	.id_table = ve_device_table,
	.probe = ve_pci_probe,
	.remove = ve_pci_remove,
};

/**
 * @brief VE Device file operations
 */
static const struct file_operations ve_fops = {
	.open = ve_drv_open,
	.flush = ve_drv_flush,
	.unlocked_ioctl = ve_drv_ioctl,
	.mmap = ve_drv_mmap,
	.release = ve_drv_release,
	.owner = THIS_MODULE,
};

/**
 * @brief Make VE chardev be able to be accessed by any user.
 *        So all interface which need privilege must be checked by capable().
 *        This is called when "ve" class is registered.
 *
 * @param[in] dev: device structure
 * @param[in] env: uevent env
 *
 * @return always 0
 */
static int ve_dev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	add_uevent_var(env, "DEVMODE=%#o", 0666);
	return 0;
}

/**
 * @brief "ve" class definition
 */
static struct class ve_class = {
	.name = "ve",
	.owner = THIS_MODULE,
	.dev_uevent = ve_dev_uevent,
};

/* EXSRAR polling timeout parameter */
int exsrar_poll_timeout_msec = 10;	/* 10msec by default */
module_param(exsrar_poll_timeout_msec, int, 0600);
MODULE_PARM_DESC(exsrar_poll_timeout_msec, "polling timeout value in msec");

/* EXSRAR polling delay parameter */
int exsrar_poll_delay_nsec = 100;	/* 100nsec by default */
module_param(exsrar_poll_delay_nsec, int, 0600);
MODULE_PARM_DESC(exsrar_poll_delay_nsec, "polling delay value in nsec");

/* HW test parameters */
int hw_intr_test_param;
module_param(hw_intr_test_param, int, 0600);
MODULE_PARM_DESC(hw_intr_test_param,
		"This parameter is used by HW test");

/* FPGA init parameters */
static int hw_skip_fpga_init;
module_param(hw_skip_fpga_init, int, 0600);
MODULE_PARM_DESC(hw_skip_fpga_init,
		 "If this parameter is not zero, driver will skip FPGA initialization.");

/* Skip FW update in probe */
static int skip_fw_update;
module_param(skip_fw_update, int, 0600);
MODULE_PARM_DESC(skip_fw_update,
		 "If this parameter is not zero, driver will skip FW Update in probe.");

/* Overwrite number of cores */
static int ow_num_of_core;
module_param(ow_num_of_core, int, 0600);
MODULE_PARM_DESC(ow_num_of_core,
		 "If this parameter is not zero, driver will overwrite number of VE cores.");

/* Overwrite core_enables */
static int ow_core_enables;
module_param(ow_core_enables, int, 0600);
MODULE_PARM_DESC(ow_core_enables,
		 "If this parameter is not zero, driver will overwrite enabled VE cores.");


static int ve_enable_irqs(struct ve_dev *vedev);

/**
 * @brief Check if the PCI device is VE-FPGA
 *
 * @param[in] pdev: PCI device structure
 *
 * @return true on FPGA. false on ASIC.
 */
static int ve_device_is_fpga(struct pci_dev *pdev)
{
	struct ve_dev *vedev = pci_get_drvdata(pdev);
	struct ve_hw_info *info = &vedev->node->hw_info;

	pdev_trace(vedev->pdev);

	if (info->model == QEMU_MODEL_0)
		return false;

	if (info->model >= 0x64)
		return true;

	return false;
}

/**
 * @brief Initialize PCI config register
 *
 * @param[in] pdev: PCI device structure
 *
 * @return 0 on success. Negative on failure.
 */
static int ve_init_pci_config(struct ve_dev *vedev)
{
	struct pci_dev *pdev = vedev->pdev;
	int ret = 0;

	/* Max read request size = 1024 */
	ret = pcie_capability_clear_and_set_word(pdev, PCI_EXP_DEVCTL,
			PCI_EXP_DEVCTL_READRQ, 0x3000);
	if (ret < 0)
		return ret;

	/* Synopsys IP (Slave AXI-to-PCIe Error Mapping) */
	ret = pci_write_config_dword(pdev, 0x8d0, 0x0000b401);
	if (ret < 0)
		return ret;

	/* Save PCI configurations */
	ret = pci_save_state(pdev);
	if (ret)
		return ret;

	/* Store saved PCI configurations */
	vedev->saved_state = pci_store_saved_state(pdev);
	if (!(vedev->saved_state))
		return -1;

	pdev_dbg(pdev, "PCI store saved state success\n");

	return 0;
}

/**
 * @brief free VE node structure
 *
 * @param[in] vedev: VE device structure
 */
static void ve_drv_del_ve_node(struct ve_dev *vedev)
{
	int entry;
	struct ve_node *node = vedev->node;

	for (entry = 0; entry < node->model_info.num_of_pciatb; entry++)
		kfree(node->mem_map[entry]);
	kfree(node->mem_map);
	for (entry = 0; entry < node->model_info.num_of_crpage; entry++)
		kfree(node->cr_map[entry]);
	kfree(node->cr_map);

	vfree(node);
}

/**
 * @brief free VE core structure
 *
 * @param[in] vedev: VE device structure
 */
static void ve_drv_fini_ve_core(struct ve_dev *vedev)
{
	struct ve_node *node = vedev->node;
	uint8_t noc = node->core_fls;
	int core_id;

	for (core_id = 0; core_id < noc; core_id++)
		kfree(node->core[core_id]);
	kfree(node->core);
}

static int ve_read_ve_config_regs(struct ve_dev *vedev, u32 *data)
{
	struct pci_dev *dev = vedev->pdev;
	int i;
	int addr;
	int ret;
	u32 *data_p;

	data_p = data;
	addr = PCI_CONFIG_VE_CONFIG_REGS_OFFSET;

	for (i = 0; i < VCR_SIZE; i++) {
		ret = pci_read_config_dword(dev, addr, &data_p[i]);
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

static int ve_drv_fill_hw_info(struct ve_dev *vedev)
{
	struct ve_hw_info *info = &vedev->node->hw_info;
	struct pci_dev *pdev = vedev->pdev;
	u32 data[VCR_SIZE];
	int ret;

	ret = ve_read_ve_config_regs(vedev, data);
	if (ret)
		return -1;

	info->model = (uint8_t)((data[0] & 0xff000000) >> 24);
	info->type = (uint8_t)((data[0] & 0x00ff0000) >> 16);
	info->cpu_version = (uint8_t)((data[0] & 0x0000ff00) >> 8);
	info->version = (uint8_t)(data[0] & 0x000000ff);
	info->num_of_core = (uint8_t)((data[1] & 0xff000000) >> 24);
	info->core_enables = data[1] & 0x00ffffff;
	info->chip_sn[0] = (uint64_t)data[2] << 32;
	info->chip_sn[0] |= (uint64_t)data[3];
	info->chip_sn[1] = (uint64_t)data[4] << 32;
	info->chip_sn[1] |= (uint64_t)data[5];
	info->board_sn[0] = (uint64_t)data[6] << 32;
	info->board_sn[0] |= (uint64_t)data[7];
	info->board_sn[1] = (uint64_t)data[8] << 32;
	info->board_sn[1] |= (uint64_t)data[9];
	info->vmcfw_version = (uint16_t)(data[10] & 0x0000ffff);
	info->memory_size = (uint16_t)((data[11] & 0xffff0000) >> 16);
	info->memory_clock = (uint16_t)(data[11] & 0x0000ffff);
	info->core_clock = (uint16_t)((data[12] & 0xffff0000) >> 16);
	info->base_clock = (uint16_t)(data[12] & 0x0000ffff);

	/*
	 * Currently memory size of FPGA is not filled in PCI config.
	 * Manually set here.
	 */
	if (ve_device_is_fpga(pdev))
		info->memory_size = (uint16_t)FPGA_MEM_SIZE;

	/* FIXME: this is workaround of HW problem */
	if (ow_core_enables)
		info->core_enables = ow_core_enables;
	if (ow_num_of_core)
		info->num_of_core = ow_num_of_core;

	pdev_dbg(pdev, "model = 0x%x\n", info->model);
	pdev_dbg(pdev, "type = 0x%x\n", info->type);
	pdev_dbg(pdev, "cpu_version = 0x%x\n", info->cpu_version);
	pdev_dbg(pdev, "version = 0x%x\n", info->version);
	pdev_dbg(pdev, "num_of_core = 0x%x\n", info->num_of_core);
	pdev_dbg(pdev, "core_enables = 0x%06x\n", info->core_enables);
	pdev_dbg(pdev, "chip_sn[0] = 0x%016llx\n", info->chip_sn[0]);
	pdev_dbg(pdev, "chip_sn[1] = 0x%016llx\n", info->chip_sn[1]);
	pdev_dbg(pdev, "board_sn[0] = 0x%016llx\n", info->board_sn[0]);
	pdev_dbg(pdev, "board_sn[1] = 0x%016llx\n", info->board_sn[1]);
	pdev_dbg(pdev, "vmcfw_version = 0x%x\n", info->vmcfw_version);
	pdev_dbg(pdev, "memory_size = 0x%x\n", info->memory_size);
	pdev_dbg(pdev, "memory_clock = 0x%x\n", info->memory_clock);
	pdev_dbg(pdev, "core_clock = 0x%x\n", info->core_clock);
	pdev_dbg(pdev, "base_clock = 0x%x\n", info->base_clock);

	/* TODO(TBD): check if every value is valid */
	if (!info->num_of_core) {
		pdev_err(pdev,
			"PCI config value num_of_core is invalid (%d)\n",
				info->num_of_core);
		return -1;
	}
	if (!info->core_enables) {
		pdev_err(pdev,
			"PCI config value core_enables is invalid (%d)\n",
				info->core_enables);
		return -1;
	}
	if (!info->memory_size) {
		pdev_err(pdev,
			"PCI config value memory_size is invalid (%d)\n",
				info->memory_size);
		return -1;
	}

	return 0;
}

static void ve_drv_fill_model_info(struct ve_dev *vedev)
{
	struct ve_hw_info *info = &vedev->node->hw_info;
	struct ve_model_info *model = &vedev->node->model_info;

	switch (info->model) {
		/*
		 * TODO(TBD): fill info by each model
		 */
	default:
		model->num_of_crpage = FPGA_CR_PAGE;
		model->num_of_pciatb = FPGA_PCIATB_ENTRY;
		model->i_cache_size = 32; /* 32 KiB */
		model->d_cache_size = 32; /* 32 KiB */
		model->l2_cache_size = 256; /* 256 KiB */
		model->l3_cache_size = 16*1024; /* 16 MiB */

	}
}

/**
 * @brief Allocate VE node structure and initialize it
 *
 * @param[in] vedev: VE device structure
 *
 * @return 0 on success.
 *         -ENOMEM on failure.
 */
static int ve_drv_init_ve_node(struct ve_dev *vedev)
{
	int i, crpage, entry, free_element;
	int ret = 0;
	struct ve_node *node;

	node = vzalloc(sizeof(struct ve_node));
	if (!node)
		return -ENOMEM;

	vedev->node = node;
	node->online_jiffies = -1;

	ret = ve_drv_fill_hw_info(vedev);
	if (ret)
		return -1;
	node->core_fls = fls(node->hw_info.core_enables);
	pdev_dbg(vedev->pdev, "core_fls = 0x%x\n", node->core_fls);
	ve_drv_fill_model_info(vedev);

	spin_lock_init(&node->lock);
	mutex_init(&node->sysfs_mutex);
	INIT_LIST_HEAD(&node->task_head);
	for (i = 0; i < NR_PD_LIST; i++) {
		mutex_init(&node->page_mutex[i]);
		hash_init(node->hash_list_head[i].head);
	}

	init_waitqueue_head(&node->waitq);
	node->cond.upper = 0;
	node->cond.lower = 0;

	/* Initialize CR page assign list */
	mutex_init(&node->crmap_mutex);
	node->cr_map = kmalloc_array(node->model_info.num_of_crpage,
			sizeof(void *), GFP_KERNEL);
	if (!(node->cr_map)) {
		ret = -ENOMEM;
		goto err_cr_map;
	}
	for (crpage = 0; crpage < node->model_info.num_of_crpage; crpage++) {
		node->cr_map[crpage] = kmalloc(sizeof(struct ve_kuid_list),
				GFP_KERNEL);
		if (!(node->cr_map[crpage])) {
			ret = -ENOMEM;
			goto err_cr_map_for;
		}
		INIT_LIST_HEAD(&node->cr_map[crpage]->list);
	}

	/* Initialize VE memory assign list */
	mutex_init(&node->pcimap_mutex);
	node->mem_map = kmalloc(sizeof(void *) *
			node->model_info.num_of_pciatb, GFP_KERNEL);
	if (!(node->mem_map)) {
		ret = -ENOMEM;
		goto err_mem_map;
	}
	for (entry = 0; entry < node->model_info.num_of_pciatb; entry++) {
		node->mem_map[entry] = kmalloc(sizeof(struct ve_kuid_list),
				GFP_KERNEL);
		if (!(node->mem_map[entry])) {
			ret = -ENOMEM;
			goto err_mem_map_for;
		}
		INIT_LIST_HEAD(&node->mem_map[entry]->list);
	}

	node->ve_state = VE_ST_UNINITIALIZED;
	node->os_state = OS_ST_OFFLINE;
#ifdef VE_DRV_DEBUG
	node->sysfs_crpage_entry = 0;
	node->sysfs_pciatb_entry = 0;
#endif

	return ret;

 err_mem_map_for:
	for (free_element = 0; free_element < entry; free_element++)
		kfree(node->mem_map[free_element]);
	kfree(node->mem_map);
	crpage = node->model_info.num_of_crpage - 1;
 err_mem_map:
 err_cr_map_for:
	for (free_element = 0; free_element < crpage; free_element++)
		kfree(node->cr_map[free_element]);
	kfree(node->cr_map);
 err_cr_map:
	return ret;
}

int ve_init_exsrar(struct ve_dev *vedev)
{
	struct pci_dev *pdev = vedev->pdev;
	struct ve_node *node = vedev->node;
	int noc = vedev->node->core_fls;
	int core_id;
	void *exsrar_reg_addr;
	off_t exsrar_offset;
	uint64_t exsrar_val;

	for (core_id = 0; core_id < noc; core_id++) {
		if (node->core[core_id]->exs != 0) {
			*(node->core[core_id]->exs) = 0;
		} else {
			pdev_info(pdev, "Core %d EXSRAR is not available\n",
					core_id);
			return -1;
		}

		exsrar_offset = PCI_BAR2_UREG_OFFSET +
			(PCI_BAR2_CREG_SIZE * core_id) +
			PCI_BAR2_SREG_OFFSET + SREG_EXSRAR_OFFSET;
		exsrar_reg_addr = vedev->bar[2] + exsrar_offset;
		exsrar_val = (uint64_t)(vedev->pdma_addr) +
			(sizeof(uint64_t) * core_id);

		/* set enable bit of EXSRAR */
		exsrar_val = (exsrar_val & ~0x3ULL) | 0x1;
		pdev_dbg(pdev, "core %d exsrar addr = %p\n", core_id,
				exsrar_reg_addr);
		pdev_dbg(pdev, "core %d exsrar write val = %llx\n",
				core_id, exsrar_val);
		/* set EXSRAR */
		ve_mmio_write64(exsrar_reg_addr, exsrar_val);
	}

	return 0;
}

/**
 * @brief Allocate ve_core structure and initialize it
 *
 * @param[in] vedev: VE device structure
 *
 * @return 0 on success.
 *         -ENOMEM on failure.
 */
static int ve_drv_init_ve_core(struct ve_dev *vedev)
{
	struct ve_node *node;
	int noc = vedev->node->core_fls;
	int core_id, free_id;

	node = vedev->node;

	/* Allocate pointers of core array */
	node->core = kmalloc_array(noc, sizeof(void *), GFP_KERNEL);
	if (!(node->core))
		return -ENOMEM;

	/* Init each cores */
	for (core_id = 0; core_id < noc; core_id++) {
		/* Allocate core structure */
		node->core[core_id] = kmalloc(sizeof(struct ve_core),
				GFP_KERNEL);
		if (!(node->core[core_id]))
			goto err;

		node->core[core_id]->node = node;
		node->core[core_id]->core_id = core_id;
		node->core[core_id]->task = NULL;
		node->core[core_id]->exs = &(vedev->vdma_addr[core_id]);
		node->core[core_id]->count =  0;
	}

	return 0;

 err:
	for (free_id = 0; free_id < core_id; free_id++)
		kfree(node->core[free_id]);
	kfree(node->core);
	return -ENOMEM;
}

/**
 * @brief Get device minor number
 *
 * @param[in] vedev: VE device structure
 *
 * @return 0 on success. Negative on failure.
 */
static int ve_get_minor(struct ve_dev *vedev)
{
	int retval = -ENOMEM;

	mutex_lock(&minor_lock);
	retval = idr_alloc(&ve_idr, vedev, 0, VE_MAX_DEVICES, GFP_KERNEL);
	if (retval >= 0) {
		vedev->minor = retval;
	} else if (retval == -ENOSPC) {
		pdev_err(vedev->pdev, "too many ve devices\n");
		retval = -EINVAL;
	}
	mutex_unlock(&minor_lock);

	return retval;
}

/**
 * @brief Free device minor number
 *
 * @param[in] vedev: VE device structure
 */
static void ve_free_minor(struct ve_dev *vedev)
{
	mutex_lock(&minor_lock);
	idr_remove(&ve_idr, vedev->minor);
	mutex_unlock(&minor_lock);
}

/**
 * @brief Returns BAR window size
 *
 * @param[in] dev: VE device structure
 * @param bar: BAR window number
 *
 * @return BAR size
 */
static unsigned long ve_get_bar_size(struct ve_dev *dev, int bar)
{
	unsigned long bar_start, bar_end;
	const struct pci_dev *pdev = dev->pdev;

	pdev_trace(pdev);

	bar_start = pci_resource_start(pdev, bar);
	bar_end = pci_resource_end(pdev, bar);
	dev->bar_size[bar] = bar_end + 1 - bar_start;

	pdev_dbg(pdev, "vedev %p bar %d: %lu(KB) (%p - %p)\n", dev, bar,
		 (unsigned long)(dev->bar_size[bar]) / 1024, (void *)bar_start,
		 (void *)bar_end);
	return dev->bar_size[bar];
}

/**
 * @brief Core interrupt handler
 *
 * @param entry: MSI-X interrupt entry
 * @param[in] pdev: pointer to a pci_dev structure
 *
 * @return IRQ_HANDLED
 */
static irqreturn_t ve_core_intr(int entry, struct pci_dev *pdev)
{
	struct ve_dev *vedev = pci_get_drvdata(pdev);
	struct ve_node *node;
	int core_id = entry;

	pdev_trace(vedev->pdev);

	node = vedev->node;

	/* HW configuration BUG */
	if (unlikely(core_id >= node->core_fls)) {
		pdev_err(vedev->pdev,
		"HW configuration BUG: entry = %d, core_enables = 0x%x\n",
			entry, node->hw_info.core_enables);
		return IRQ_HANDLED;
	}

	spin_lock(&vedev->node->lock);
	/* increment interrupt count */
	node->core[core_id]->count++;

	/* in case of other arch than x86 */
	smp_wmb();

	if (node->core[core_id]->task != NULL) {
		node->core[core_id]->task->wait_cond = 1;
		wake_up_interruptible(&node->core[core_id]->task->waitq);
		goto clear_intvec;
	}
	pdev_dbg(vedev->pdev, "no task to be awaken (core %d count = %d)\n",
	       core_id, node->core[core_id]->count);

 clear_intvec:
	/* Clear Interrupt Vector Register */
	ve_bar2_write64_20(vedev,
			PCI_BAR2_SCR_OFFSET + CREG_INTERRUPT_VECTOR,
			(uint64_t)0x8000000000000000 >> core_id);

	spin_unlock(&vedev->node->lock);

	return IRQ_HANDLED;
}

/**
 * @brief DMA and error interrupt handler
 *
 * @param entry: MSI-X interrupt entry
 * @param[in] pdev: pointer to a pci_dev structure
 *
 * @return IRQ_HANDLED
 */
static irqreturn_t ve_intr_notify(int entry, struct pci_dev *pdev)
{
	struct ve_dev *vedev = pci_get_drvdata(pdev);
	struct ve_node *node = vedev->node;
	uint64_t cond_bit = 0;

	pdev_trace(vedev->pdev);

	/* set condition bit */
	spin_lock(&node->lock);
	if (entry < 64) {
		cond_bit = 0x1ULL << entry;
		node->cond.lower |= cond_bit;
	} else {
		entry -= 64;
		cond_bit = 0x1ULL << entry;
		node->cond.upper |= cond_bit;
	}
	spin_unlock(&node->lock);

	/* wake up */
	wake_up_interruptible(&node->waitq);

	return IRQ_HANDLED;
}

/**
 * @brief convert irq into MSI-X entry
 *
 * @param irq: the interrupt number
 * @param vedev: VE device structure
 *
 * @return MSI-X entry number on success.
 *         -1 on failure.
 */
inline int ve_msix_vec_to_entry(int irq, struct ve_dev *vedev)
{
	int entry;

	for (entry = 0; entry < vedev->msix_nvecs; entry++) {
		if (irq == vedev->msix_entries[entry].vector)
			return entry;
	}
	return -1;
}

static void dump_hw_error_log(struct ve_dev *vedev, int entry)
{
	struct pci_dev *pdev = vedev->pdev;

	if (entry != 0xff)
		pdev_err(pdev, "HW Error occurred (Entry = %d)\n", entry);
}

/**
 * @brief Generic interrupt handler
 *
 * @param irq: the interrupt number
 * @param[in] arg: pointer to a pci_dev structure
 *
 * @return IRQ_HANDLED
 */
static irqreturn_t ve_intr(int irq, void *arg)
{
	struct pci_dev *pdev = arg;
	struct ve_dev *vedev = pci_get_drvdata(pdev);
	int entry;

	entry = ve_msix_vec_to_entry(irq, vedev);
	pdev_dbg(vedev->pdev, "Entry = %d\n", entry);

	if (unlikely(entry < 0 || 95 < entry))
		return IRQ_HANDLED;

	if (unlikely(entry > 63))
		dump_hw_error_log(vedev, entry);

	if (entry < 16 && likely(!hw_intr_test_param))
		return ve_core_intr(entry, pdev);

	return ve_intr_notify(entry, pdev);
}

/**
 * @brief Finalize interruption of the device.
 *
 * @param[in] vedev VE device structure
 */
static void ve_disable_irqs(struct ve_dev *vedev)
{
	int entry;
	struct pci_dev *pdev;

	pdev_trace(vedev->pdev);

	pdev = vedev->pdev;

	if (pdev->msix_enabled) {
		for (entry = 0; entry < vedev->msix_nvecs; entry++)
			free_irq(vedev->msix_entries[entry].vector, pdev);
		pci_disable_msix(pdev);
		kfree(vedev->msix_entries);
	}
}

/**
 * @brief Map IO memory.
 *
 * @param[in] dev: VE device structure
 *
 * @return: 0 on success. negative on failure.
 */
static int ve_map_bar(struct ve_dev *dev)
{
	int bar, bar_unmap;
	unsigned long size;

	for (bar = 0; bar < PCI_NUM_RESOURCES; bar++) {
		if (!(dev->bars & (1 << bar)))
			continue;
		size = ve_get_bar_size(dev, bar);
		if (size <= 0)
			goto err;
		dev->pbar[bar] = pci_resource_start(dev->pdev, bar);
		if (!(dev->pbar[bar])) {
			pdev_err(dev->pdev,
				"pci_resource_start for BAR%d was failed\n",
				bar);
			goto err;
		}

		/*
		 * Note:
		 * Max 128MB is mapped to kernel virtual address to avoid
		 * memory consumption of page table
		 */
		if (size > 0x8000000) {
			pdev_dbg(dev->pdev,
		"BAR%d map is truncated to %x (actual size is %lx)\n",
				bar, 0x8000000, size);
			size = 0x8000000;
		}

		dev->bar[bar] = ioremap_nocache(dev->pbar[bar], size);
		if (dev->bar[bar] == NULL) {
			pdev_err(dev->pdev, "ioremap for BAR%d was failed\n",
					bar);
			goto err;
		}
		pdev_dbg(dev->pdev, "dev->pbar[%d] = %p ,dev->bar[%d] = %p\n",
			 bar, (char *)dev->pbar[bar], bar, dev->bar[bar]);
	}

	return 0;

 err:
	for (bar_unmap = 0; bar_unmap < bar; bar_unmap++) {
		if (!(dev->bars & (1 << bar_unmap)))
			continue;
		iounmap(dev->bar[bar_unmap]);
	}
	return -1;
}

/**
 * @brief Unmap IO memory.
 *
 * @param dev VE device structure
 */
static void ve_unmap_bar(struct ve_dev *dev)
{
	int bar;

	/* BAR4 and BAR5 are for MSI-X */
	for (bar = 0; bar < PCI_NUM_RESOURCES; bar++) {
		if (dev->bars & (1 << bar))
			iounmap(dev->bar[bar]);
	}
}

static void ve_drv_stop_all_cores_dmas(struct ve_dev *dev)
{
	struct ve_hw_info *info = &dev->node->hw_info;
	struct pci_dev *pdev = dev->pdev;
	int core_id;
	off_t offset;
	uint64_t regdata;
	unsigned long to_jiffies;

	pdev_trace(pdev);
	/*
	 * STOP all the cores and DMAs
	 */
	offset = PCI_BAR2_SCR_OFFSET + CREG_DMACTLP_OFFSET;
	ve_bar2_write64(dev, offset, DMACTL_DISABLE_PERMIT);

	for (core_id = 0; core_id < dev->node->core_fls; core_id++) {
		if (!(info->core_enables & (1 << core_id)))
			continue;

		/* Set core register offset */
		offset = PCI_BAR2_UREG_OFFSET +
			PCI_BAR2_CREG_SIZE * core_id;

		/* STOP the user DMA (Host) */
		ve_bar2_write64(dev, offset +
				PCI_BAR2_SREG_OFFSET +
				SREG_DMACTLH_OFFSET,
				DMACTL_DISABLE_PERMIT);

		/* STOP the user DMA (Device) */
		ve_bar2_write64(dev, offset +
				PCI_BAR2_SREG_OFFSET +
				SREG_DMACTLE_OFFSET,
				DMACTL_DISABLE_PERMIT);

		/* STOP the core */
		ve_bar2_write64(dev, offset +
				PCI_BAR2_UREG_OFFSET +
				UREG_EXS_OFFSET,
				EXS_STATE_STOP);
	}

	to_jiffies = jiffies + msecs_to_jiffies(VE_REMOVE_TIMEOUT_MSECS);
	/*
	 * Check if all the cores and all the DMAs are stopped
	 */
	offset = PCI_BAR2_SCR_OFFSET + CREG_DMACTLP_OFFSET;
	do {
		ve_bar2_read64(dev, offset, &regdata);
		if (regdata & DMACTL_HALT_MASK)
			break;
		if (time_after(jiffies, to_jiffies)) {
			pdev_dbg(pdev, "PDMA stop timed out (0x%llx)\n",
					regdata);
			goto force_stop;
		}
	} while (1);

	for (core_id = 0; core_id < dev->node->core_fls; core_id++) {
		if (!(info->core_enables & (1 << core_id)))
			continue;

		/* Set core register offset */
		offset = PCI_BAR2_UREG_OFFSET + PCI_BAR2_CREG_SIZE * core_id;

		/* Check the user DMA (Host) */
		do {
			ve_bar2_read64(dev, offset +
					PCI_BAR2_SREG_OFFSET +
					SREG_DMACTLH_OFFSET,
					&regdata);
			if (regdata & DMACTL_HALT_MASK)
				break;
			if (time_after(jiffies, to_jiffies)) {
				pdev_dbg(pdev,
				"Core %d UDMAH stop timed out (0x%llx)\n",
				core_id, regdata);
				goto force_stop;
			}
		} while (1);

		/* Check the user DMA (Device) */
		do {
			ve_bar2_read64(dev, offset +
					PCI_BAR2_SREG_OFFSET +
					SREG_DMACTLE_OFFSET,
					&regdata);
			if (regdata & DMACTL_HALT_MASK)
				break;
			if (time_after(jiffies, to_jiffies)) {
				pdev_dbg(pdev,
				"Core %d UDMAE stop timed out (0x%llx)\n",
				core_id, regdata);
				goto force_stop;
			}
		} while (1);

		/* Check the core */
		do {
			ve_bar2_read64(dev, offset +
					PCI_BAR2_UREG_OFFSET +
					UREG_EXS_OFFSET,
					&regdata);
			if (!(regdata & EXS_STATE_RUN))
				break;
			if (time_after(jiffies, to_jiffies)) {
				pdev_dbg(pdev,
				"Core %d stop timed out (0x%llx)\n",
				core_id, regdata);
				goto force_stop;
			}
		} while (1);
	}

	return;
force_stop:
	pdev_dbg(pdev, "core and dma stop timed out\n");
	pci_clear_master(pdev);
}

/**
 * @brief Check if the PCI device needs firmware update
 *
 * @param[in] pdev: PCI device structure
 *
 * @return true if it needs update. false if it doesn't.
 */
static int ve_device_needs_firm_update(struct ve_dev *vedev)
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

	switch (info->model) {
	case ASIC_MODEL_0:
	case ASIC_MODEL_1:
		return true;
	case FPGA_MODEL_104:
	case FPGA_MODEL_105:
	case FPGA_MODEL_106:
	case FPGA_MODEL_107:
	case QEMU_MODEL_0:
		return false;
	default:
		pdev_warn(pdev, "Unsupported Device (model = 0x%x)\n",
				info->model);
		return false;
	}
}

static int ve_prepare_for_link_down(struct ve_dev *vedev, u16 *aer_cap, int sbr)
{
	struct pci_dev *pdev = vedev->pdev;
	struct pci_dev *parent = pdev->bus->self;
	int err;

	pdev_trace(vedev->pdev);

	/*
	 * Set target linkspeed of SW/RP downstream port to Gen1
	 * before secondary bus reset
	 */
	if (sbr) {
		err = ve_set_lnkctl2_target_speed(parent, 1);
		if (err) {
			pdev_err(pdev,
				"Failed to set Link Control 2 Register\n");
			return -1;
		}
	}
	/*
	 * Check AER status of the PCI bus this device is on
	 */
	err = pcie_capability_read_word(parent, PCI_EXP_DEVCTL, aer_cap);
	if (err) {
		pdev_err(parent,
				"pcie_capability_read_word failed. (%d)\n",
				err);
	} else if (*aer_cap & PCI_EXP_AER_FLAGS) {
		/* AER should be disabled temporarily if it is enabled */
		err = pci_disable_pcie_error_reporting(parent);
		pdev_dbg(parent, "AER is temporarily disabled\n");
	} else
		pdev_dbg(parent, "AER is not enabled (did nothing)\n");

	return err;
}

static int ve_prepare_for_chip_reset(struct ve_dev *vedev, u16 *aer_cap,
		int disable_irq, int sbr)
{
	pdev_trace(vedev->pdev);

	/* Disable MSI-X */
	if (disable_irq)
		ve_disable_irqs(vedev);

	return ve_prepare_for_link_down(vedev, aer_cap, sbr);
}

static int ve_check_pci_link(struct pci_dev *pdev)
{
	int ret = 0;
	u16 vendor;

	/* Dummy write */
	pci_write_config_word(pdev, PCI_VENDOR_ID, 0);

	ret = pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	if (ret) {
		pdev_dbg(pdev, "Reading VendorID failed, err %d\n",
				ret);
		return 1;
	}
	if (vendor == 0xffff) {
		pdev_dbg(pdev, "Reading VendorID is all 1s\n");
		return 1;
	}

	pdev_dbg(pdev, "Reading VendorID success (0x%x)\n", vendor);
	return 0;
}

/* Copied from drivers/pci/pci.c */
static struct pci_cap_saved_state *_pci_find_saved_cap(struct pci_dev *pci_dev,
		u16 cap, bool extended)
{
	struct pci_cap_saved_state *tmp;

	hlist_for_each_entry(tmp, &pci_dev->saved_cap_space, next) {
		if (tmp->cap.cap_extended == extended && tmp->cap.cap_nr == cap)
			return tmp;
	}
	return NULL;
}

/* Copied from drivers/pci/pci.c */
struct pci_cap_saved_state *pci_find_saved_cap(struct pci_dev *dev, char cap)
{
	return _pci_find_saved_cap(dev, cap, false);
}

/**
 * Save LNKCTL2 to reserve current state
 * This is modified version of pci_save_pcie_state() in drivers/pci/pci.c
 */
static int pci_save_state_lnkctl2_only(struct pci_dev *dev)
{
	int i = 0;
	struct pci_cap_saved_state *save_state;
	u16 *cap;

	if (!pci_is_pcie(dev))
		return 0;

	save_state = pci_find_saved_cap(dev, PCI_CAP_ID_EXP);
	if (!save_state) {
		dev_err(&dev->dev, "buffer not found in %s\n", __func__);
		return -ENOMEM;
	}

	cap = (u16 *)&save_state->cap.data[0];
	/* PCI_EXP_DEVCTL */
	i++;
	/* PCI_EXP_LNKCTL */
	i++;
	/* PCI_EXP_SLTCTL */
	i++;
	/* PCI_EXP_RTCTL */
	i++;
	/* PCI_EXP_DEVCTL2 */
	i++;
	/* PCI_EXP_LNKCTL2 */
	pcie_capability_read_word(dev, PCI_EXP_LNKCTL2, &cap[i++]);
	/* PCI_EXP_SLTCTL2 */
	i++;

	return 0;
}


static int ve_recover_from_link_down(struct ve_dev *vedev, u16 *aer_cap,
		int fw_update, int sbr)
{
	struct pci_dev *pdev = vedev->pdev;
	struct pci_dev *parent = pdev->bus->self;
	int err;
	int train_count;
	u16 link_ctl, link_sta;
	unsigned long start_jiffies;

	pdev_trace(vedev->pdev);

	err = ve_check_pci_link(pdev);
	if (err) {
		pdev_err(pdev, "PCI link is not recovered\n");
		return -1;
	}

	/*
	 * Load and free stored state
	 * Since pci_load_saved_state() is not exported,
	 * we load and free here and then store again.
	 */
	err = pci_load_and_free_saved_state(pdev, &vedev->saved_state);
	if (err) {
		pdev_err(pdev, "PCI link is not recovered\n");
		return -1;
	}
	vedev->saved_state = pci_store_saved_state(pdev);
	if (!(vedev->saved_state)) {
		pdev_err(pdev, "Failed to store PCI saved state\n");
		return -1;
	}

	/* Save current state of lnkctl2 on FW udpating */
	if (fw_update)
		pci_save_state_lnkctl2_only(pdev);
	/* Restore PCI config */
	pci_restore_state(pdev);
	pdev_dbg(pdev, "PCI config is restored\n");

	/* Do link retraining only after FW updating */
	if (!fw_update || sbr)
		goto train_end;
	/* Skip if it is already linked with Gen3 */
	pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_sta);
	if ((link_sta & PCI_EXP_LNKSTA_CLS_8_0GB) == PCI_EXP_LNKSTA_CLS_8_0GB)
		goto train_end;

	/* Link training */
	train_count = 3;
 link_train:
	pcie_capability_read_word(parent, PCI_EXP_LNKCTL, &link_ctl);
	link_ctl |= PCI_EXP_LNKCTL_RL;
	pcie_capability_write_word(parent, PCI_EXP_LNKCTL, link_ctl);

	/* We need to wait for the link coming up. */
	pdev_dbg(pdev, "Starting link training\n");
	start_jiffies = jiffies;
	for (;;) {
		pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_sta);
		if (!(link_sta & PCI_EXP_LNKSTA_LT))
			break;
		if (time_after(jiffies, start_jiffies + HZ))
			break;
		msleep(20);
	}
	train_count--;
	if (!(link_sta & PCI_EXP_LNKSTA_LT)) {
		pdev_dbg(parent, "link training success\n");
	} else {
		pdev_err(parent, "link training failed\n");
		return -1;
	}

	/*
	 * After PCIe link is up, confirm link speed.
	 * Then if it's not linked with Gen3 (or Gen2),
	 * generate link retraining here.
	 */
	if ((link_sta & PCI_EXP_LNKSTA_CLS_8_0GB) == PCI_EXP_LNKSTA_CLS_8_0GB) {
		pdev_dbg(pdev, "Gen3 link was established. (LNKSTA = 0x%x)\n",
				link_sta);
		goto train_end;
	} else if (train_count > 0)
		goto link_train;

	pdev_info(pdev, "Gen3 link was not established. (LNKSTA = 0x%x)\n",
		 link_sta);
 train_end:
	/* AER config should be restored */
	if (*aer_cap & PCI_EXP_AER_FLAGS) {
		err = pci_enable_pcie_error_reporting(parent);
		pdev_dbg(parent, "AER is re-enabled\n");
	}

	return 0;
}

static int ve_recover_from_chip_reset(struct ve_dev *vedev, u16 *aer_cap,
		int enable_irq, int fw_update, int sbr)
{
	int err;

	pdev_trace(vedev->pdev);

	/* Restore PCI config and link retrain to link with Gen3 */
	err = ve_recover_from_link_down(vedev, aer_cap, fw_update, sbr);
	if (err)
		return err;

	/* Enable MSI-X */
	if (enable_irq) {
		/* clear all pending interrupt bits in driver */
		vedev->node->cond.lower = 0;
		vedev->node->cond.upper = 0;

		err = ve_enable_irqs(vedev);
		if (err)
			return err;
	}

	/* FPGA specific initialization */
	if (ve_device_is_fpga(vedev->pdev) && !hw_skip_fpga_init) {
		/* initialize FPGA */
		err = ve_init_fpga(vedev);
		if (err) {
			pdev_err(vedev->pdev, "fail to initialize FPGA (%d)\n",
					err);
			return err;
		}
	}

	return 0;
}

static inline void do_link_down_eif_inh(struct ve_dev *vedev)
{
	pdev_trace(vedev->pdev);

	ve_bar2_write64(vedev, LINK_DOWN_EIF_INH_OFFSET,
			LINK_DOWN_EIF_INH_DATA);
}

static inline void do_ve_chip_reset(struct ve_dev *vedev)
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
	pci_reset_bridge_secondary_bus(parent);
}

static int ve_reset_and_fwupdate(struct ve_dev *vedev, uint64_t sbr,
		int update_only, int irq)
{
	struct pci_dev *pdev = vedev->pdev;
	int err;
	u16 aer_cap;

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
		do_ve_chip_reset(vedev);

	/* Wait 1 sec */
	ssleep(1);

	/* Skip FW loading */
	goto recover_chip_reset;

 load_fw:
	err = ve_device_needs_firm_update(vedev);
	if (err == false)
		goto recover_chip_reset;

	/*
	 * Load PCIe Gen3 firmware here. And then chip will be reset.
	 * We need to wait for a while for the PCIe link comes up.
	 */
	pdev_info(pdev, "Loading PCIe Firmware\n");

	err = ve_load_gen3_firmware(vedev);
	if (err) {
		pdev_err(pdev, "Failed to load PCIe Firmware\n");
		(void)ve_recover_from_chip_reset(vedev, &aer_cap, irq,
				update_only, 0);
		return err;
	}

 recover_chip_reset:
	err = ve_recover_from_chip_reset(vedev, &aer_cap, irq, update_only,
			sbr);

	return err;
}

int ve_chip_reset_sbr(struct ve_dev *vedev, uint64_t sbr)
{
	int irq = 1;
	int err = 0;

	mutex_lock(&vedev->node->sysfs_mutex);
	if (vedev->node->os_state != OS_ST_OFFLINE) {
		err = -EAGAIN;
		goto err_state;
	}
	if (sbr)
		irq = 0;
	err = ve_reset_and_fwupdate(vedev, sbr, 0, irq);

 err_state:
	mutex_unlock(&vedev->node->sysfs_mutex);
	return err;
}

int ve_firmware_update(struct ve_dev *vedev)
{
	int err = 0;

	mutex_lock(&vedev->node->sysfs_mutex);
	if (vedev->node->os_state != OS_ST_OFFLINE) {
		err = -EAGAIN;
		goto err_state;
	}
	err = ve_reset_and_fwupdate(vedev, 0, 1, 1);

 err_state:
	mutex_unlock(&vedev->node->sysfs_mutex);
	return err;
}

/**
 * @brief Enable MSI/MSI-X interrupts and request irqs.
 *
 * @param[in] vedev: device to enable interrupt
 *
 * @return 0 on success. Negative on failure.
 */
static int ve_enable_irqs(struct ve_dev *vedev)
{
	int entry, free_entry;
	int err = -1;
	struct pci_dev *pdev;

	pdev_trace(vedev->pdev);

	pdev = vedev->pdev;
	vedev->msix_nvecs = pci_msix_vec_count(pdev);
	if (!(vedev->msix_nvecs)) {
		pdev_err(pdev, "MSI-X is not available\n");
		goto err_msix_count;
	}
	vedev->msix_entries = kcalloc(vedev->msix_nvecs,
				      sizeof(struct msix_entry), GFP_KERNEL);
	if (!(vedev->msix_entries))
		goto err_msix_count;
	for (entry = 0; entry < vedev->msix_nvecs; entry++)
		vedev->msix_entries[entry].entry = entry;

	/*
	 * pci_enable_msix doesn't return positive when nvec is obtained
	 * by pci_msix_vec_count(). So something is wrong with previous code
	 * if this returns positive value.
	 */
	err = pci_enable_msix(pdev, vedev->msix_entries, vedev->msix_nvecs);
	if (err < 0) {
		pdev_err(pdev, "Failed to enable MSI-X\n");
		goto err_enable_msix;
	} else if (err > 0) {
		pdev_err(pdev, "Failed to count MSI-X vector. (%d)\n", err);
		err = -1;
		goto err_enable_msix;
	}

	for (entry = 0; entry < vedev->msix_nvecs; entry++) {
		err = request_irq(vedev->msix_entries[entry].vector,
				  ve_intr, 0, ve_driver_name, pdev);
		if (err) {
			pdev_err(pdev, "request_irq of vector %d failed.(%d)\n",
				 vedev->msix_entries[entry].vector, err);
			goto err_request_irq;
		}
		pdev_dbg(pdev, "MSI-X is enabled. vector = %d, entry = %d\n",
			 vedev->msix_entries[entry].vector,
			 vedev->msix_entries[entry].entry);
	}

	return 0;

 err_request_irq:
	for (free_entry = 0; free_entry < entry; free_entry++)
		free_irq(vedev->msix_entries[free_entry].vector, pdev);
	pci_disable_msix(pdev);

 err_enable_msix:
	kfree(vedev->msix_entries);
 err_msix_count:

	return err;
}

/**
 * @brief
 * PCI device initialization Routine
 * ve_pci_probe is called by PCI subsystem when the driver is loaded and
 * the device is found.
 *
 * @param[in] pdev: pci_dev structure to probe
 * @param[in] id: pci_device_id structure to probe
 *
 * @return: 0 on success. negative on failure.
 */
static int ve_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int err = -1;
	int minor;
	dev_t devt;
	struct ve_dev *vedev;

	pdev_trace(pdev);

	vedev = kzalloc(sizeof(struct ve_dev), GFP_KERNEL);
	if (!vedev)
		return -1;
	vedev->pdev = pdev;
	pci_set_drvdata(pdev, vedev);

	/* Get minor number */
	minor = ve_get_minor(vedev);
	if (minor < 0) {
		err = minor;
		goto err_minor;
	}

	pci_set_master(pdev);

	/*
	 * PCI resource initialization
	 */
	vedev->bars = pci_select_bars(pdev, IORESOURCE_MEM);
	pdev_dbg(pdev, "bars = 0x%x\n", vedev->bars);

	/* BAR 01, 2, 3, 4, 5 is required for VE */
	if (!(vedev->bars & 0x3e)) {
		pdev_err(pdev, "Insufficient BARs(0x%x)\n",
				vedev->bars);
		goto err_pci_bar;
	}

	/* Enable device memory */
	err = pci_enable_device_mem(pdev);
	if (err) {
		pdev_err(pdev, "pci_enable_device_mem failed. (%d)\n", err);
		goto err_pci_enable;
	} else
		pdev_dbg(pdev, "PCI device mem is enabled\n");

	/* Tell PCI subsystem that this module use BARs */
	err = pci_request_selected_regions(pdev, vedev->bars, ve_driver_name);
	if (err) {
		pdev_err(pdev,
			 "pci_request_selected_regions failed. (%d)\n", err);
		goto err_pci_reg;
	} else
		pdev_dbg(pdev, "PCI request regions successed\n");

	/* Map BARs */
	err = ve_map_bar(vedev);
	if (err)
		goto err_map_bar;

	/* Check DMA availability */
	if (!dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
		pdev_dbg(pdev, "64 bit DMA address is supported\n");
	} else if (!dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32))) {
		pdev_dbg(pdev, "32 bit DMA address is supported\n");
	} else {
		pdev_err(pdev, "No suitable DMA available\n");
		err = -EIO;
		goto err_init_dma;
	}

	/* allocate coherent DMA address (use for EXSRAR target) */
	vedev->vdma_addr = dma_zalloc_coherent(&pdev->dev,
					       sizeof(uint64_t) *
					       VE_MAX_CORE_NUM,
					       &vedev->pdma_addr, GFP_KERNEL);
	if (!(vedev->vdma_addr))
		goto err_dma_alloc;

	pdev_dbg(pdev, "vedev->pdma_addr = %llx\n", vedev->pdma_addr);

	/* init internal structures */
	err = ve_drv_init_ve_node(vedev);
	if (err) {
		pdev_err(pdev, "Failed to init VE node structure (%d).\n", err);
		goto err_init_node;
	}

	err = ve_init_pci_config(vedev);
	if (err) {
		pdev_err(pdev, "Failed to init PCI config (%d).\n", err);
		goto err_init_pci;
	}

	/* Update Firmware */
	if (!skip_fw_update) {
		err = ve_reset_and_fwupdate(vedev, 0, 1, 0);
		if (err && err != -EIO)
			goto err_fw_update;
	}

	err = ve_drv_init_ve_core(vedev);
	if (err)
		goto err_init_core;

	err = ve_init_exsrar(vedev);
	if (err)
		goto err_init_core;

	/* Clear interrupt mask register */
	ve_bar2_write64_20(vedev,
			PCI_BAR2_SCR_OFFSET + CREG_INTERRUPT_VECTOR, ~0ULL);

	/* get dev_t */
	devt = MKDEV(ve_major, minor);

	/* init cdev */
	cdev_init(&(vedev->cdev), &ve_fops);
	vedev->cdev.owner = THIS_MODULE;

	/* Add character device */
	err = cdev_add(&vedev->cdev, devt, 1);
	if (err < 0) {
		pdev_err(pdev, "fail to add cdev (%d)\n", err);
		goto err_cdev_create;
	}

	/* Create sysfs device */
	vedev->device = device_create(&ve_class, &pdev->dev, devt, NULL,
				      "ve%d", minor);
	if (IS_ERR(vedev->device)) {
		err = PTR_ERR(vedev->device);
		pdev_err(pdev, "device_create failed (%d)\n", err);
		vedev->device = NULL;
		goto err_device_create;
	}

	dev_set_drvdata(vedev->device, vedev);
	err = ve_drv_init_sysfs(vedev);
	if (err)
		goto err_sysfs;

	err = ve_enable_irqs(vedev);
	if (err) {
		pdev_err(pdev, "ve_enable_irqs failed (%d)\n", err);
		goto err_enable_msi;
	}

	pdev_info(pdev, "probe succeeded\n");

	return 0;

 err_enable_msi:
	ve_drv_fini_sysfs(vedev);
 err_sysfs:
	device_unregister(vedev->device);
 err_device_create:
	cdev_del(&vedev->cdev);
 err_cdev_create:
	ve_drv_fini_ve_core(vedev);
 err_init_core:
 err_fw_update:
	pci_load_and_free_saved_state(pdev, &vedev->saved_state);
 err_init_pci:
	ve_drv_del_ve_node(vedev);
 err_init_node:
	dma_free_coherent(&pdev->dev, sizeof(uint64_t) * VE_MAX_CORE_NUM,
			  vedev->vdma_addr, vedev->pdma_addr);
 err_dma_alloc:
 err_init_dma:
	ve_unmap_bar(vedev);
 err_map_bar:
	pci_release_selected_regions(pdev, vedev->bars);
 err_pci_reg:
 err_pci_enable:
	pci_disable_device(pdev);
 err_pci_bar:
	ve_free_minor(vedev);
 err_minor:
	kfree(vedev);

	pdev_err(pdev, "probe error (return %d)\n", err);

	return err;
}

/**
 * @brief
 * PCI device removal Routine
 * ve_pci_remove is called by PCI subsystem when the driver is going to be
 * removeed from the system.
 *
 * @param[in] pdev: PCI device structure
 */
static void ve_pci_remove(struct pci_dev *pdev)
{
	int i;
	struct ve_dev *vedev;

	pdev_trace(pdev);
	vedev = pci_get_drvdata(pdev);

	pdev_dbg(pdev, "remove vedev %p\n", vedev);

	/* free irqs */
	ve_disable_irqs(vedev);
	pdev_dbg(pdev, "ve_fini_intr done\n");

	/* remove sysfs */
	ve_drv_fini_sysfs(vedev);

	/* remove device */
	device_unregister(vedev->device);
	pdev_dbg(pdev, "device_unregister done\n");

	/* remove chardev */
	cdev_del(&vedev->cdev);
	pdev_dbg(pdev, "cdev_del done\n");

	/* stop all memory transfer */
	ve_drv_stop_all_cores_dmas(vedev);
	/* release pages */
	for (i = 0; i < NR_PD_LIST; i++)
		vp_page_release_all(&vedev->node->hash_list_head[i]);

	/* free structures */
	ve_drv_del_all_task(vedev);
	ve_drv_fini_ve_core(vedev);
	pci_load_and_free_saved_state(pdev, &vedev->saved_state);
	ve_drv_del_ve_node(vedev);

	/* unmap BARs */
	ve_unmap_bar(vedev);
	pdev_dbg(pdev, "iounmap done\n");

	/* free DMA coherent for EXSRAR */
	dma_free_coherent(&pdev->dev, sizeof(uint64_t) * VE_MAX_CORE_NUM,
			  vedev->vdma_addr, vedev->pdma_addr);

	/* release BARs */
	pci_release_regions(pdev);
	pdev_dbg(pdev, "pci_release_regions done\n");

	/* disable bus mastering */
	pci_disable_device(pdev);
	pdev_dbg(pdev, "pci_disable_device done\n");

	/* free minor number */
	ve_free_minor(vedev);
	pdev_dbg(pdev, "minor number removed\n");

	kfree(vedev);
}

/**
 * @brief
 * VE driver module initialization routine
 * This is called when the driver is loaded to the system.
 *
 * @return: 0 on success. negative on failure.
 */
static int __init ve_drv_init(void)
{
	int ret;
	dev_t ve_devt;

	pr_debug("%s: __init", ve_driver_name);

	pr_info("%s: %s - version %s %s\n", ve_driver_name, ve_driver_string,
		VERSION, RELEASE);
	pr_info("%s: %s\n", ve_driver_name, ve_copyright);

	/* allocate major number and minor number */
	ret = alloc_chrdev_region(&ve_devt, 0, VE_MAX_DEVICES, ve_driver_name);
	if (ret < 0) {
		pr_err("%s: can't allocate major (%d)\n", ve_driver_name, ret);
		return ret;
	}
	ve_major = MAJOR(ve_devt);
	pr_debug("%s: ve_devt major = %d\n", ve_driver_name, ve_major);
	ret = class_register(&ve_class);
	if (ret)
		goto err_class_register;

	ret = pci_register_driver(&ve_drv_pci_driver);
	if (!ret)
		return 0;

	class_unregister(&ve_class);
 err_class_register:
	unregister_chrdev_region(MKDEV(ve_major, 0), VE_MAX_DEVICES);

	return ret;
}
module_init(ve_drv_init);

/**
 * @brief
 * Clean up routine of VE driver module
 * This is called just before the driver is removed from the system.
 */
static void __exit ve_drv_fini(void)
{
	pr_debug("%s __exit", ve_driver_name);

	unregister_chrdev_region(MKDEV(ve_major, 0), VE_MAX_DEVICES);
	pci_unregister_driver(&ve_drv_pci_driver);
	pr_debug("%s: unregister PCI driver done\n", ve_driver_name);
	class_unregister(&ve_class);
	pr_debug("%s: unregister ve class done\n", ve_driver_name);
	idr_destroy(&ve_idr);
}
module_exit(ve_drv_fini);
