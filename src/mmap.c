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
 * @file mmap.c
 * @brief VE driver vm operations.
 */

#include <linux/kernel.h>
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

#include <linux/uaccess.h>
#include <linux/version.h>
#if (KERNEL_VERSION(4, 18, 0) <= LINUX_VERSION_CODE)
#include <linux/cred.h>
#endif
#include "ve_drv.h"
#include "internal.h"

static void ve_vm_open(struct vm_area_struct *);
static void ve_vm_close(struct vm_area_struct *);
#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
static int ve_vm_fault(struct vm_area_struct *, struct vm_fault *);
#elif (KERNEL_VERSION(4, 17, 0) > LINUX_VERSION_CODE)
static int ve_vm_fault(struct vm_fault *);
#else
static vm_fault_t ve_vm_fault(struct vm_fault *);
#endif

#ifdef VE_DRV_DEBUG
int ve_access_phys(struct vm_area_struct *vma, unsigned long addr,
		void *buf, int len, int write)
{
	struct ve_dev *vedev = vma->vm_private_data;

	pdev_trace(vedev->pdev);

	return generic_access_phys(vma, addr, buf, len, write);
}
#endif

/**
 * @brief VM operation structure for VE I/O memory mapping
 */
static const struct vm_operations_struct ve_vm_ops = {
	.open = ve_vm_open,
	.close = ve_vm_close,
	.fault = ve_vm_fault,
#ifdef VE_DRV_DEBUG
	.access = ve_access_phys,
#endif
};

/**
 * @brief mmap method of vm operation for VE driver
 *
 * @param[in] filp: file struct of mmaping
 * @param[in,out] vma: vm area struct of mmaping
 *
 * @return 0 on success.
 *         -EINVAL if the offset of mmap is invalid.
 *         -EACCES if this is not permitted.
 */
int ve_drv_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct ve_task *task = vma->vm_file->private_data;
	struct ve_dev *vedev = task->vedev;
	unsigned long offset, size, bar_offset, flags;
	int bar, err;

	vma->vm_private_data = vedev;

	pdev_trace(vedev->pdev);

	spin_lock_irqsave(&vedev->node->lock, flags);
	/* block mmap device will be deleted */
	if( vedev->remove_processing ){
		spin_unlock_irqrestore(&vedev->node->lock, flags);
		pdev_dbg(vedev->pdev,"device will be deleted, mmap is blocked\n");
		return 	-ENODEV;
	}
	/* reject mmap when mm_struct is held */
	if (task->mm) {
		pdev_dbg(vedev->pdev,
				"mm_struct is held. reject mmap.\n");
		spin_unlock_irqrestore(&vedev->node->lock, flags);
		return -EACCES;
	}
	task->mmap = true;
	spin_unlock_irqrestore(&vedev->node->lock, flags);

	/* check range */
	offset = vma->vm_pgoff << PAGE_SHIFT;
	size = vma->vm_end - vma->vm_start;

	if (unlikely(offset + size < offset)) {
		pdev_dbg(vedev->pdev,
			"invalid offset/size: offset=0x%lx, size=0x%lx\n",
		       offset, size);
		return -EINVAL;
	}

	BUG_ON(vedev->arch_class->ve_arch_map_range_offset == 0);
	err = vedev->arch_class->ve_arch_map_range_offset(vedev, offset, size,
							&bar, &bar_offset);
	if (err !=0) {
		pdev_dbg(vedev->pdev,
			"unmappable (%d): offset=0x%lx, size=0x%lx\n", err,
			offset, size);
		return err;
	}
	
	pdev_dbg(vedev->pdev,
		"BAR%d map (offset=0x%lx, size=0x%lx) to virt addr [%p - %p]\n",
		bar, bar_offset, size,
		(void *)vma->vm_start, (void *)vma->vm_end);

	/* Change page protection for preventing caching */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	/*
	 * Set vm_operations_struct.
	 * Actual mapping is done at the time of page fault.
	 */
	vma->vm_ops = &ve_vm_ops;

	/* Set vm_flags */
	vma->vm_ops->open(vma);

	return 0;
}

/**
 * @brief open method of vm operation for VE
 *
 * @param[in,out] vma: vm area struct of opening
 */
static void ve_vm_open(struct vm_area_struct *vma)
{
	struct ve_dev *vedev = vma->vm_private_data;

	pdev_trace(vedev->pdev);

	/*
	 * This vma is NOT managed by struct page (just PFN)
	 * This vma is memory mapped I/O
	 * This vma must NOT be copied on fork
	 */
	vma->vm_flags |= VM_PFNMAP | VM_IO | VM_DONTCOPY;
}

/**
 * @brief close method of vm operation for VE
 *
 * @param[in,out] vma: vm area struct of closing
 */
static void ve_vm_close(struct vm_area_struct *vma)
{
	struct ve_dev *vedev = vma->vm_private_data;

	pdev_trace(vedev->pdev);
}

/**
 * @brief check the current task may use PCIATB entry
 *
 * @param vedev: VE device
 * @param entry: PCIATB entry number
 *
 * @return 0 if current is permitted to map the area corresponding to the entry.
 *         Negative if current is not permitted to map the area.
 */
int ve_drv_check_pciatb_entry_permit(const struct ve_dev *vedev, int entry)
{
	struct ve_node *node = vedev->node;
	struct list_head *ptr, *head;
	struct ve_kuid_list *uid_list;
	kuid_t kuid = current_uid();

	pdev_trace(vedev->pdev);

	head = &node->mem_map[entry]->list;
	mutex_lock(&node->pcimap_mutex);
	list_for_each (ptr, head) {
		uid_list = list_entry(ptr, struct ve_kuid_list, list);
		if (uid_eq(uid_list->kuid, kuid)) {
			mutex_unlock(&node->pcimap_mutex);
			return 0;
		}
	}
	mutex_unlock(&node->pcimap_mutex);
	return -1;
}

/**
 * @brief check the current task may map CR area
 *
 * @param vedev: VE device
 * @param entry: CR page entry number
 *
 * @return 0 if current is permitted to map the area corresponding to the entry.
 *         Negative if current is not permitted to map the area.
 *
 */
int ve_drv_check_cr_entry_permit(const struct ve_dev *vedev, int entry)
{
	struct ve_node *node = vedev->node;
	struct list_head *ptr, *head;
	struct ve_kuid_list *uid_list;
	kuid_t kuid = current_uid();

	pdev_trace(vedev->pdev);
	head = &node->cr_map[entry]->list;
	mutex_lock(&node->crmap_mutex);
	list_for_each (ptr, head) {
		uid_list = list_entry(ptr, struct ve_kuid_list, list);
		if (uid_eq(uid_list->kuid, kuid)) {
		  mutex_unlock(&node->crmap_mutex);
		  return 0;
		}
	}
	mutex_unlock(&node->crmap_mutex);
	return -1;
}

/**
 * @brief fault method of vm operation for VE
 *        (Page fault handler)
 *
 * @param[in,out] vma: vm area of faulting
 * @param[in] vmf: fault information
 *
 * @return VM_FAULT_NOPAGE on success.
 *         VM_FAULT_SIGBUS on failure.
 */
#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
static int ve_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#elif (KERNEL_VERSION(4, 17, 0) > LINUX_VERSION_CODE)

static int ve_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#else
static vm_fault_t ve_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#if (RHEL_RELEASE_VERSION(8,2) <= RHEL_RELEASE_CODE)
	vm_fault_t fault_reason;
#endif
#endif
	unsigned long offset, bar_offset, pfn;
	int err;
	struct ve_dev *vedev = vma->vm_private_data;
	unsigned long vaddr_start;
	int bar = -1;

	pdev_trace(vedev->pdev);

	offset = vmf->pgoff << PAGE_SHIFT;
	err = vedev->arch_class->ve_arch_map_range_offset(vedev,offset,
					PAGE_SIZE, &bar, &bar_offset);
	if (err != 0) {
		pdev_dbg(vedev->pdev, "fault at invalid offset: offset=0x%lx\n",
		       offset);
#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
		pdev_dbg(vedev->pdev,
		       "(vma->vm_pgoff = %lu, vmf->pgoff = %lu)(addr = %p)\n",
			vma->vm_pgoff, vmf->pgoff, vmf->virtual_address);
#else
		pdev_dbg(vedev->pdev,
		       "(vma->vm_pgoff = %lu, vmf->pgoff = %lu)(addr = %lu)\n",
			vma->vm_pgoff, vmf->pgoff, vmf->address);
#endif
		return VM_FAULT_SIGBUS;
	}

	if (bar >= 0)
		pfn = (vedev->pbar[bar] + bar_offset) >> PAGE_SHIFT;
	else
		return VM_FAULT_SIGBUS;

	/*
	 * BAR0 and BAR3 security check
	 * and return VM_FAULT_SIGBUS if it is not permitted.
	 */
	err = vedev->arch_class->permit_to_map(vedev, bar, bar_offset);
	if (err)
		return VM_FAULT_SIGBUS;
#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
	vaddr_start = ((unsigned long)vmf->virtual_address) & PAGE_MASK;
#else
	vaddr_start = ((unsigned long)vmf->address) & PAGE_MASK;
#endif

#if (RHEL_RELEASE_VERSION(8,2) > RHEL_RELEASE_CODE)
	pdev_dbg(vedev->pdev, "vm_insert_pfn (va=%p, pfn=%lu)\n",
			(void *)vaddr_start, pfn);
	err = vm_insert_pfn(vma, vaddr_start, pfn);
	if (err == 0 || err == -EBUSY)
		return VM_FAULT_NOPAGE;

	pdev_err(vedev->pdev,
			"vm_insert_pfn(va=%p, pfn=%lu): returned %d\n",
			(void *)vaddr_start, pfn, err);
#else
	pdev_dbg(vedev->pdev, "vmf_insert_pfn (va=%p, pfn=%lu)\n",
			(void *)vaddr_start, pfn);
	fault_reason = vmf_insert_pfn(vma, vaddr_start, pfn);
	if (fault_reason == VM_FAULT_NOPAGE)
		return VM_FAULT_NOPAGE;

	pdev_err(vedev->pdev,
			"vmf_insert_pfn(va=%p, pfn=%lu): returned %d\n",
			(void *)vaddr_start, pfn, fault_reason);
#endif
	return VM_FAULT_SIGBUS;
}

/**
 * @brief Unmap all area regarding VE address space
 *        This is called via ioctl
 *
 * @param[in] vedev: VE device structure
 *
 * @return 0 on success.
 *         -EFAULT when copy_from_user() fail.
 */
int ve_unmap_mapping(struct ve_dev *vedev, struct ve_unmap *usr)
{
	int err;
	struct address_space *mapping = vedev->dev_mapping;
	struct ve_unmap arg;

	pdev_trace(vedev->pdev);

	err = copy_from_user(&arg, usr, sizeof(struct ve_unmap));
	if (err)
		return -EFAULT;

	if (arg.offset + arg.size - 1 < arg.offset)
		return -EINVAL;

	pdev_dbg(vedev->pdev, "unmapping from 0x%016lx to 0x%016lx\n",
			arg.offset, arg.offset + arg.size - 1);
	unmap_mapping_range(mapping, arg.offset,
			arg.offset + arg.size - 1, 1);

	return 0;
}

