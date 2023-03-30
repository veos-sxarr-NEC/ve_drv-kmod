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
 * @file main.c
 * @brief VE driver main file.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/aer.h>
#include <linux/idr.h>
#include <linux/dma-mapping.h>
#include <linux/vmalloc.h>
#include <linux/kref.h>
#include <linux/sched/signal.h>
#include "../config.h"
#include "commitid.h"
#include "ve_drv.h"
#include "internal.h"
#include "mmio.h"
#define VE_MAX_DEVICES         (1U << MINORBITS)
#define VE_REMOVE_TIMEOUT_MSECS	40

/* static strings */
char ve_driver_name[] = "ve_drv";
static const char ve_driver_string[] = "NEC Vector Engine Driver";
static const char ve_copyright[] = "Copyright (c) 2020 NEC Corporation.";
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
	{PCI_DEVICE(PCI_VENDOR_ID_VE1, PCI_DEVICE_ID_VE1)},
	{PCI_DEVICE(PCI_VENDOR_ID_VE3, PCI_DEVICE_ID_VE3_EMULATOR)},
	{PCI_DEVICE(PCI_VENDOR_ID_VE3, PCI_DEVICE_ID_VE3)},{0,},
};

typedef const struct ve_arch_class *ve_arch_probe_func_t(struct ve_dev *);
/**
 * @brief VE model/type probe functions
 */
static ve_arch_probe_func_t *ve_arch_probe_table[] = {
	ve_arch_probe_ve1,
	ve_arch_probe_ve3,
	0,
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
 * @brief Probe VE architecture model/type
 *
 */
const struct ve_arch_class *ve_drv_probe_arch_class(struct ve_dev *vedev)
{
	const struct ve_arch_class *ret;
	struct pci_dev *pdev = vedev->pdev;
	ve_arch_probe_func_t **p;
	for (p = ve_arch_probe_table; *p; ++p) {
		ret = (**p)(vedev);
		if (ret > 0) {
			pdev_dbg(pdev, "probe succeeded (%s)\n",
				ret->name);
			return ret;
		}
	}
	pdev_err(pdev, "arch probe failure: no arch type matched\n");
	return NULL;
}

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

/* Wait time after VE ESET parameter */
int wait_after_vereset_sec = 16;	/* 15sec by default */
module_param(wait_after_vereset_sec, int, 0600);
MODULE_PARM_DESC(wait_after_vereset_sec, "wait time after vereset value in sec");


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

/* clear INTVEC on PCI access exception */
int clear_intvec_pci_access_exception;
module_param(clear_intvec_pci_access_exception, int, 0600);
MODULE_PARM_DESC(clear_intvec_pci_access_exception,
                 "If this parameter is not zero, driver will clear INTVEC on PCI access exception (MSI-X 34).");

int panic_on_pci_access_exception;
module_param(panic_on_pci_access_exception, int, 0600);
MODULE_PARM_DESC(panic_on_pci_access_exception,
                 "If this parameter is not zero, driver will panic on PCI access exception (MSI-X 34).");

int wait_sec_after_sigterm_on_remove=10;
module_param(wait_sec_after_sigterm_on_remove, int, 0600);
MODULE_PARM_DESC(wait_sec_after_sigterm_on_remove,
                 "This parameter is wait time after send sigterm on remove function.");

int wait_sec_after_sigkill_on_remove=5;
module_param(wait_sec_after_sigkill_on_remove, int, 0600);
MODULE_PARM_DESC(wait_sec_after_sigkill_on_remove,
                 "This parameter is wait time after send sigkill on remove function.");

int wait_sec_after_sigkill_on_notify_fault=10;
module_param(wait_sec_after_sigkill_on_notify_fault, int, 0600);
MODULE_PARM_DESC(wait_sec_after_sigkill_on_notify_fault,
                 "This parameter is wait time after send sigkill on notify fault function.");



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
	vedev->arch_class->fini_node(vedev, node);

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
	node->sensor_rawdata = kzalloc(vedev->arch_class->num_sensors *
				sizeof(node->sensor_rawdata[0]), GFP_KERNEL);
	if (!node->sensor_rawdata){
	        ret = -ENOMEM;
		goto err_alloc_sensor_rawdata;
	}	
	node->ve_archdep_data = kzalloc(vedev->arch_class->ve_archdep_size,
					GFP_KERNEL);
	if (!node->ve_archdep_data){
	        ret = -ENOMEM;
		goto err_alloc_archdep_data;
	}
	vedev->node = node;
	node->online_jiffies = -1;

	BUG_ON(vedev->arch_class->fill_hw_info == 0);
	ret = vedev->arch_class->fill_hw_info(vedev);
	if (ret)
		goto err_fill_hw_info;

	node->core_fls = fls(node->hw_info.core_enables);
	pdev_dbg(vedev->pdev, "core_fls = 0x%x\n", node->core_fls);
	BUG_ON(vedev->arch_class->fill_model_info == 0);
	vedev->arch_class->fill_model_info(vedev, &vedev->node->model_info);

	spin_lock_init(&node->lock);
	mutex_init(&node->sysfs_mutex);
	INIT_LIST_HEAD(&node->task_head);
	for (i = 0; i < NR_PD_LIST; i++) {
		mutex_init(&node->page_mutex[i]);
		hash_init(node->hash_list_head[i].head);
	}

	init_waitqueue_head(&node->waitq);
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

	node->os_state = OS_ST_OFFLINE;

	node->ownership = NULL;
	node->notifyfaulter = NULL;
#ifdef VE_DRV_DEBUG
	node->sysfs_crpage_entry = 0;
	node->sysfs_pciatb_entry = 0;
#endif
	if (vedev->arch_class->init_node) {
		ret = vedev->arch_class->init_node(vedev, node);
		if (ret != 0) {
			goto err_arch_init_node;
		}
	}

	return ret;

 err_arch_init_node:
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
 err_fill_hw_info:
	kfree(node->ve_archdep_data);
 err_alloc_archdep_data:
	kfree(node->sensor_rawdata);
 err_alloc_sensor_rawdata:
	vfree(node);
	vedev->node = NULL;

	return ret;
}

int ve_init_exsrar(struct ve_dev *vedev)
{
	struct pci_dev *pdev = vedev->pdev;
	struct ve_node *node = vedev->node;
	int noc = vedev->node->core_fls;
	int core_id;
	void *exsrar_reg_addr;
	uint64_t exsrar_val;

	void *(*exsrar_addr_func)(const struct ve_dev *, int);
	exsrar_addr_func = vedev->arch_class->exsrar_addr;
	BUG_ON(exsrar_addr_func == 0);

	for (core_id = 0; core_id < noc; core_id++) {
		if (node->core[core_id]->exs != 0) {
			*(node->core[core_id]->exs) = 0;
		} else {
			pdev_info(pdev, "Core %d EXSRAR is not available\n",
					core_id);
			return -1;
		}

		exsrar_reg_addr = exsrar_addr_func(vedev, core_id);
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
 * @param[in] pdev: pointer to a pci_dev structure
 * @param core_id: core_id
 * @param irq_handled_cb: callback when the core interrupt is handled.
 *                        node->lock in ve_dev is held on callback.
 *
 * @return IRQ_HANDLED
 */
irqreturn_t ve_drv_generic_core_intr(struct ve_dev *vedev, int core_id,
			void (*irq_handled_cb)(struct ve_dev *, int))
{
	struct ve_node *node;
	unsigned long flags;

	pdev_trace(vedev->pdev);

	node = vedev->node;

	/* HW configuration BUG */
	if (unlikely(core_id >= node->core_fls)) {
		pdev_err(vedev->pdev,
		"HW configuration BUG: core_id = %d, core_enables = 0x%lx\n",
			core_id, (unsigned long)node->hw_info.core_enables);
		return IRQ_HANDLED;
	}

	spin_lock_irqsave(&vedev->node->lock, flags);
	/* increment interrupt count */
	node->core[core_id]->count++;

	/* in case of other arch than x86 */
	smp_wmb();

	if (node->core[core_id]->task != NULL) {
		node->core[core_id]->task->wait_cond = 1;
		wake_up_interruptible(&node->core[core_id]->task->waitq);
		goto callback;
	}
	pdev_dbg(vedev->pdev, "no task to be awaken (core %d count = %d)\n",
	       core_id, node->core[core_id]->count);

 callback:
	irq_handled_cb(vedev, core_id);

	spin_unlock_irqrestore(&vedev->node->lock, flags);

	return IRQ_HANDLED;
}

/**
 * @brief Generic node interrupt handler
 *
 * Invoke a specified callback and wake up a process on node wait queue
 *
 * @param[in] pdev: pointer to a pci_dev structure
 * @param irq_handled_cb: callback
 *                        node->lock in ve_dev is held on callback.
 *
 * @return IRQ_HANDLED
 */
irqreturn_t ve_drv_generic_node_intr(struct ve_dev *vedev, int entry,
		void (*irq_handled_cb)(struct ve_dev *, int entry))
{
	struct ve_node *node = vedev->node;
	unsigned long flags;

	pdev_trace(vedev->pdev);
	spin_lock_irqsave(&node->lock, flags);
	irq_handled_cb(vedev, entry);
	spin_unlock_irqrestore(&node->lock, flags);
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
	return vedev->arch_class->ve_arch_intr(vedev, entry);
}

/**
 * @brief Finalize interruption of the device.
 *
 * @param[in] vedev VE device structure
 */
void ve_drv_disable_irqs(struct ve_dev *vedev)
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
	struct pci_dev *pdev = dev->pdev;
	unsigned long to_jiffies;
	int stopped;
	pdev_trace(pdev);

	BUG_ON(dev->arch_class->request_stop_all == 0);
	BUG_ON(dev->arch_class->check_stopped == 0);

	dev->arch_class->request_stop_all(dev);

	to_jiffies = jiffies + msecs_to_jiffies(VE_REMOVE_TIMEOUT_MSECS);

	do {
		stopped = dev->arch_class->check_stopped(dev);
		if (stopped)
			break;
		if (time_after(jiffies, to_jiffies)) {
			goto force_stop;
		}
	} while (1);
	return;
force_stop:
	pdev_dbg(pdev, "core and dma stop timed out\n");
	pci_clear_master(pdev);
}

/**
 * @brief Enable MSI/MSI-X interrupts and request irqs.
 *
 * @param[in] vedev: device to enable interrupt
 *
 * @return 0 on success. Negative on failure.
 */
int ve_drv_enable_irqs(struct ve_dev *vedev)
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
#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
	err = pci_enable_msix(pdev, vedev->msix_entries, vedev->msix_nvecs);
	if (err < 0) {
		pdev_err(pdev, "Failed to enable MSI-X\n");
		goto err_enable_msix;
	} else if (err > 0) {
		pdev_err(pdev, "Failed to count MSI-X vector. (%d)\n", err);
		err = -1;
		goto err_enable_msix;
	}

#else
	err = pci_enable_msix_range(pdev, vedev->msix_entries, vedev->msix_nvecs,vedev->msix_nvecs);
	if (err < 0) {
		pdev_err(pdev, "Failed to enable MSI-X\n");
		goto err_enable_msix;
	} else if (err != vedev->msix_nvecs ) {
		pdev_err(pdev, "Failed to count MSI-X vector. (%d)\n", err);
		err = -1;
		goto err_enable_msix;
	}

#endif

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


int ve_prepare_for_link_down(struct ve_dev *vedev, u16 *aer_cap,
					int sbr)
{
	struct pci_dev *pdev = vedev->pdev;
	struct pci_dev *parent = pdev->bus->self;
	int err;
	int err_discard;
	pdev_trace(vedev->pdev);

	/*
	 * Set target linkspeed of SW/RP downstream port to Gen1
	 * before secondary bus reset
	 */
	if (sbr == 1) {
		err = ve_drv_set_lnkctl2_target_speed(parent, 1);
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
		pdev_err(parent, "pcie_capability_read_word failed. (%d)\n",
				err);
	} else if (*aer_cap & PCI_EXP_AER_FLAGS) {
		/* AER should be disabled temporarily if it is enabled */
	        /* ignore err 48740 */
		err_discard = pci_disable_pcie_error_reporting(parent);
		pdev_dbg(parent, "AER is temporarily disabled (%d:%d)\n", err,err_discard);
	} else
		pdev_dbg(parent, "AER is not enabled (did nothing)\n");

	return err;
}

int ve_prepare_for_chip_reset(struct ve_dev *vedev, u16 *aer_cap,
		int disable_irq, int sbr)
{
	pdev_trace(vedev->pdev);

	/* Disable MSI-X */
	if (disable_irq)
		ve_drv_disable_irqs(vedev);

	return ve_prepare_for_link_down(vedev, aer_cap, sbr);
}

int ve_check_pci_link(struct pci_dev *pdev)
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

int ve_recover_from_link_down(struct ve_dev *vedev, u16 *aer_cap,
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
	if (!fw_update || (sbr == 1))
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


/**
 * @brief Enable Gen3 Link mode
 *
 * @param pdev PCI device structure
 *
 * @return 0 on success. Negative on failure.
 */
int ve_drv_set_lnkctl2_target_speed(struct pci_dev *pdev, u8 link_speed)
{
	int err;
	u16 link_ctl2;

	if (link_speed > 0x7) {
		pdev_err(pdev, "invalid linkspeed is specified.\n");
		return -1;
	}

	/* Read Link Control 2 Register (PCIe r3.0-complient)  */
	err = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL2, &link_ctl2);
	if (err) {
		pdev_err(pdev, "Failed to read Link Control 2 Register\n");
		return -1;
	}
	if ((link_ctl2 & 0xf) == link_speed) {
		pdev_dbg(pdev, "link speed is already set\n");
		return 0;
	}

	/* set target link speed */
	link_ctl2 &= ~0xf;
	link_ctl2 |= link_speed;
	pcie_capability_write_word(pdev, PCI_EXP_LNKCTL2, link_ctl2);
	pdev_info(pdev, "link cntrol 2 register is set (0x%x)\n", link_ctl2);

	return 0;
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

	kref_init(&vedev->ve_dev_ref);
	kref_init(&vedev->final_ref);
	/* ref=2 for remove and release */
	ve_drv_final_get(vedev);
	init_waitqueue_head(&vedev->release_q);
	vedev->remove_processing = false;

	/* Get minor number */
	minor = ve_get_minor(vedev);
	if (minor < 0) {
		err = minor;
		goto err_minor;
	}

	vedev->arch_class = ve_drv_probe_arch_class(vedev);
	if (vedev->arch_class == NULL) {
		err = -EINVAL;
		goto err_arch_probe;
	}

	if (vedev->arch_class->init_early) {
		err = vedev->arch_class->init_early(vedev);
		if (err){
			pdev_err(pdev,
				 "failed init_early(%d)",
				 err);
			/*
			 * not error return
			 */
		}
	}

	pci_set_master(pdev);

	/*
	 * PCI resource initialization
	 */
	vedev->bars = pci_select_bars(pdev, IORESOURCE_MEM);
	pdev_dbg(pdev, "bars = 0x%x\n", vedev->bars);

	/* check BARs */
	if (vedev->bars != vedev->arch_class->expected_bar_mask) {
		pdev_err(pdev, "Insufficient BARs(0x%x != 0x%x)\n",
			vedev->bars, vedev->arch_class->expected_bar_mask);
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
					vedev->arch_class->max_core_num,
					&vedev->pdma_addr, GFP_KERNEL);
	if (!(vedev->vdma_addr)){
		err = -EIO;
		goto err_dma_alloc;
	}
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

	/*
	 * initialization after preparing ve_node:
	 * e.g. update firmware
	 */
	if (vedev->arch_class->init_post_node) {
		err = vedev->arch_class->init_post_node(vedev);
		if (err) {
			pdev_err(pdev,
				"failed initialization after ve_node (%d)",
				err);
			goto err_init_post_node;
		}
	}
	if (vedev->arch_class->init_hw_check) {
		err = vedev->arch_class->init_hw_check(vedev);
		if (err) {
			pdev_err(pdev,
				"failed hw init check or numa config (%d)",
				err);
			/*
			 * not error return
			 */

		}
	}
	err = ve_drv_init_ve_core(vedev);
	if (err)
		goto err_init_core;

	/*
	 * initialization after preparing ve_node:
	 * e.g. clear INTVEC mask
	 */
	if (vedev->arch_class->init_post_core) {
		err = vedev->arch_class->init_post_core(vedev);
		if (err) {
			pdev_err(pdev,
				"failed initialization after ve_core (%d)",
				err);
			goto err_init_post_core;
		}
	}

	err = ve_init_exsrar(vedev);
	if (err)
		goto err_init_core;

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

	err = ve_drv_enable_irqs(vedev);
	if (err) {
		pdev_err(pdev, "ve_drv_enable_irqs failed (%d)\n", err);
		goto err_enable_msi;
	}

	if (vedev->arch_class->init_hw_check)
		sysfs_notify(&vedev->device->kobj, NULL, "ve_state");


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
 err_init_post_core:
 err_init_core:
 err_init_post_node:
	pci_load_and_free_saved_state(pdev, &vedev->saved_state);
 err_init_pci:
	ve_drv_del_ve_node(vedev);
 err_init_node:
	dma_free_coherent(&pdev->dev,
			  sizeof(uint64_t) * vedev->arch_class->max_core_num,
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
	if (vedev->arch_class->fini_late)
		vedev->arch_class->fini_late(vedev);

 err_arch_probe:
	ve_free_minor(vedev);
 err_minor:
	kfree(vedev);

	pdev_err(pdev, "probe error (return %d)\n", err);

	return err;
}

/**
 * @brief final remove ve software resource
 *
 * @param[in] vedev: VE device structure
 */
static void ve_remove_final(struct kref *kref)
{
	struct ve_dev *vedev = container_of(kref,struct ve_dev, final_ref);
	pr_debug("ve_remove_final in\n");

	/* free core structures */
	ve_drv_fini_ve_core(vedev);
	pr_debug("core structures removed\n");

	/* free node structures */
	ve_drv_del_ve_node(vedev);
	pr_debug("node structures removed\n");

	kfree(vedev);
	pr_debug("ve_remove_final out\n");
}

/*
 * @brief de reference vedev
 *
 * @param[in] vedev: VE device structure
 */
void ve_drv_final_put(struct ve_dev *vedev)
{
	kref_put(&vedev->final_ref, ve_remove_final);
}

/**
 * @brief reference final vedev
 *
 * @param[in] vedev: VE device structure
 */
void ve_drv_final_get(struct ve_dev *vedev)
{
	kref_get(&vedev->final_ref);
}

/**
 * @brief wakeup remove process
 *
 * @param[in] vedev: VE device structure
 */
static void ve_wakeup_remove(struct kref *kref)
{
	struct ve_dev *vedev = container_of(kref,struct ve_dev, ve_dev_ref);
	wake_up(&vedev->release_q);
	ve_drv_final_put(vedev);
}

/**
 * @brief de reference vedev
 *
 * @param[in] vedev: VE device structure
 */
void ve_drv_device_put(struct ve_dev *vedev)
{
	kref_put(&vedev->ve_dev_ref, ve_wakeup_remove);
}

/**
 * @brief reference vedev
 *
 * @param[in] vedev: VE device structure
 */
void ve_drv_device_get(struct ve_dev *vedev)
{
	kref_get(&vedev->ve_dev_ref);
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
	int wsec;
	unsigned long flags;
	struct list_head *head, *ptr, *n;
	struct ve_task *task;
	struct ve_node *node;
	int rv;

	pdev_trace(pdev);
	vedev = pci_get_drvdata(pdev);

	node = vedev->node;
	head = &node->task_head;

	pdev_dbg(pdev, "remove vedev %p\n", vedev);

	/*
	 * subsequent new open, ioctl, mmap  will be block and return with -ENODEV
	 */
	spin_lock_irqsave(&node->lock, flags);
	vedev->remove_processing = true;
	spin_unlock_irqrestore(&node->lock, flags);
	pdev_dbg(pdev, "subsequent block done\n");


	/*
	 * if no one is open, decrement ref count and call wakeup(),
	 * but, wakeup () doesn't make sense. Because it wait after this _put()
	 */
	ve_drv_device_put(vedev);


	/*
	 * First send SIGTERM to successfully terminate all open processes on
	 *  the device.
	 */
	spin_lock_irqsave(&node->lock, flags);
	list_for_each_safe(ptr, n, head) {
		task = list_entry(ptr, struct ve_task, list);
		rv = kill_pid(task->pid, SIGTERM, 1);
		pdev_info(pdev,
			  "send SIGTERM to process %d when device removing\n",
			  pid_vnr(task->pid));
		if (rv < 0) {
			pdev_err(pdev,
				 "Error send end SIGTERM to Process %d(%d)\n",
				 pid_vnr(task->pid), rv);
		}
	}
	spin_unlock_irqrestore(&node->lock, flags);

	wsec = 0;
	do {
		rv = wait_event_interruptible_timeout(vedev->release_q,
						      kref_read(&vedev->ve_dev_ref)
						      == 0,
						      msecs_to_jiffies(1000));
	} while( kref_read(&vedev->ve_dev_ref) != 0 &&
		 ++wsec < wait_sec_after_sigterm_on_remove &&
		 rv != -ERESTARTSYS );


	if ( kref_read(&vedev->ve_dev_ref) != 0 ){
		pdev_warn(vedev->pdev,
			  "someone is still using the device (%d) (%d)\n",
			  kref_read(&vedev->ve_dev_ref), rv );
	}else {
		pdev_info(vedev->pdev, "device reference (%d) (%d)\n",
			  kref_read(&vedev->ve_dev_ref), rv );
	}

	/* wake up processes in task->waitq_dead  */
	ve_drv_del_all_task(vedev);
	pdev_dbg(pdev, "wakeup task waitq_dead  done\n");
	/*
	 * wake up all processes in the interrupt wait queue
	 */
	wake_up_interruptible_all(&vedev->node->waitq);
	pdev_dbg(pdev, "wakeup node waitq  done\n");

	/*
	 * Finally, if there are still processes to open the device, kill them
	 * all. this will call the ve_drv_release() at context of opend process.
	 * process.However, this is not the best finsh for the application.
	 */
	spin_lock_irqsave(&node->lock, flags);
	list_for_each_safe(ptr, n, head) {
		task = list_entry(ptr, struct ve_task, list);
		rv = kill_pid(task->pid, SIGKILL, 1);
		pdev_info(pdev,
			  "send SIGKILL to process %d when device removing\n",
			  pid_vnr(task->pid));
		if (rv < 0) {
			pdev_err(pdev, "Error killing Process %d(%d)\n",
				 pid_vnr(task->pid), rv);
		}
	}
	spin_unlock_irqrestore(&node->lock, flags);

	/*
	 * Wait for all processes that opened this VE to complete the release
	 * (close). if kref_read() == 0 , No one is open, so wake up immediately
	 * without waiting.
	 * N.B.
	 * release() use sysfs for notify so can't do after ve_drv_fini_sysfs().
	 */
	//wait_event(vedev->release_q,  kref_read(&vedev->ve_dev_ref) == 0);
	wsec = 0;
	do {
		rv = wait_event_interruptible_timeout(vedev->release_q,
						      kref_read(&vedev->ve_dev_ref)
						      == 0,
						      msecs_to_jiffies(1000));
	} while( kref_read(&vedev->ve_dev_ref) != 0 &&
		 ++wsec < wait_sec_after_sigkill_on_remove &&
		 rv != -ERESTARTSYS );

	if ( kref_read(&vedev->ve_dev_ref) != 0 ){
		pdev_err(vedev->pdev,
			 "someone is still using the device (%d) (%d)\n",
			 kref_read(&vedev->ve_dev_ref), rv );
	}

	/* stop all memory transfer */
	ve_drv_stop_all_cores_dmas(vedev);
	/* disable bus mastering */
	pci_clear_master(pdev);

	/* free irqs */
	ve_drv_disable_irqs(vedev);
	pdev_dbg(pdev, "ve_fini_intr done\n");
	/*
	 * if someone get ownership, someone may be wait for release.
	 * notify waiter, but waiter can't get ownerhisp.
	 */
	spin_lock_irqsave(&node->lock, flags);
	if(vedev->node->ownership){
		vedev->node->ownership = NULL;
		sysfs_notify(&vedev->device->kobj, NULL,"ownership");
		/*
		 * noone can get ownership, because already remove_processing
		 * is set ,so block next ioctl to get ownership.
		 */
		pdev_dbg( vedev->pdev,"fource ownership to NULL at remove\n");
	}
	spin_unlock_irqrestore(&node->lock, flags);

	/* remove sysfs */
	ve_drv_fini_sysfs(vedev);

	/* remove device */
	device_unregister(vedev->device);
	pdev_dbg(pdev, "device_unregister done\n");

	/* remove chardev */
	cdev_del(&vedev->cdev);
	pdev_dbg(pdev, "cdev_del done\n");


	/* release pages */
	for (i = 0; i < NR_PD_LIST; i++)
		vp_page_release_all(&vedev->node->hash_list_head[i]);

	pci_load_and_free_saved_state(pdev, &vedev->saved_state);

	/* unmap BARs */
	ve_unmap_bar(vedev);
	pdev_dbg(pdev, "iounmap done\n");

	/* free DMA coherent for EXSRAR */
	dma_free_coherent(&pdev->dev,
			  sizeof(uint64_t) * vedev->arch_class->max_core_num,
			  vedev->vdma_addr, vedev->pdma_addr);

	/* release BARs */
	pci_release_regions(pdev);
	pdev_dbg(pdev, "pci_release_regions done\n");

	/* finalizer after unmapping PCI resources */
	if (vedev->arch_class->fini_late)
		vedev->arch_class->fini_late(vedev);

	/* disable bus mastering */
	pci_disable_device(pdev);
	pdev_dbg(pdev, "pci_disable_device done\n");

	/* free minor number */
	ve_free_minor(vedev);
	pdev_dbg(pdev, "minor number removed\n");

	/*
	 * de reference vedev
	 */
	ve_drv_final_put(vedev);

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
